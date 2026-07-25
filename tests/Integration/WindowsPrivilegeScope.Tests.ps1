BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:scopePrivilege = 'SeSecurityPrivilege'
    $script:restorePrivilege = 'SeRestorePrivilege'
    $script:enabledPrivilege = 'SeChangeNotifyPrivilege'
    $tokenPrivilegeNames = @(Get-WindowsPrivilege).Name
    $script:absentPrivilege = @(
        'SeTcbPrivilege'
        'SeCreateTokenPrivilege'
        'SeTrustedCredManAccessPrivilege'
    ) | Where-Object { $_ -notin $tokenPrivilegeNames } | Select-Object -First 1

    foreach ($requiredPrivilege in $script:scopePrivilege, $script:restorePrivilege) {
        if ($requiredPrivilege -notin $tokenPrivilegeNames) {
            throw "The elevated test token does not contain $requiredPrivilege."
        }
    }
}

AfterAll {
    Enable-WindowsPrivilege -Name $script:enabledPrivilege -Confirm:$false -ErrorAction SilentlyContinue
    Disable-WindowsPrivilege -Name $script:scopePrivilege -Confirm:$false -ErrorAction SilentlyContinue
    Disable-WindowsPrivilege -Name $script:restorePrivilege -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Scoped Windows privilege lifecycle' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        Disable-WindowsPrivilege -Name $script:scopePrivilege -Confirm:$false
        Disable-WindowsPrivilege -Name $script:restorePrivilege -Confirm:$false
        Enable-WindowsPrivilege -Name $script:enabledPrivilege -Confirm:$false
    }

    It 'Should enable a held privilege only for the script block' {
        $inside = InModuleScope WindowsAccessControl -Parameters @{
            PrivilegeName = $script:scopePrivilege
        } {
            Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock {
                Test-WindowsPrivilege -Name $PrivilegeName
            }
        }

        $inside | Should -BeTrue
        Test-WindowsPrivilege -Name $script:scopePrivilege | Should -BeFalse
    }

    It 'Should keep a privilege enabled until the outer nested scope exits' {
        $states = InModuleScope WindowsAccessControl -Parameters @{
            PrivilegeName = $script:scopePrivilege
        } {
            Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock {
                $inner = Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock {
                    Test-WindowsPrivilege -Name $PrivilegeName
                }
                [pscustomobject]@{
                    Inner      = $inner
                    AfterInner = Test-WindowsPrivilege -Name $PrivilegeName
                }
            }
        }

        $states.Inner | Should -BeTrue
        $states.AfterInner | Should -BeTrue
        Test-WindowsPrivilege -Name $script:scopePrivilege | Should -BeFalse
    }

    It 'Should deduplicate the same privilege name within one scope' {
        $inside = InModuleScope WindowsAccessControl -Parameters @{
            PrivilegeName = $script:scopePrivilege
        } {
            Invoke-WithWindowsPrivilege -Name $PrivilegeName, $PrivilegeName -ScriptBlock {
                Test-WindowsPrivilege -Name $PrivilegeName
            }
        }

        $inside | Should -BeTrue
        Test-WindowsPrivilege -Name $script:scopePrivilege | Should -BeFalse
    }

    It 'Should restore a privilege when the script block throws' {
        {
            InModuleScope WindowsAccessControl -Parameters @{
                PrivilegeName = $script:scopePrivilege
            } {
                Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock {
                    throw 'Expected scope failure.'
                }
            }
        } | Should -Throw -ExpectedMessage '*Expected scope failure*'

        Test-WindowsPrivilege -Name $script:scopePrivilege | Should -BeFalse
    }

    It 'Should leave an initially enabled privilege enabled' {
        $inside = InModuleScope WindowsAccessControl -Parameters @{
            PrivilegeName = $script:enabledPrivilege
        } {
            Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock {
                Test-WindowsPrivilege -Name $PrivilegeName
            }
        }

        $inside | Should -BeTrue
        Test-WindowsPrivilege -Name $script:enabledPrivilege | Should -BeTrue
    }

    It 'Should name a privilege that is absent from the token' {
        if (-not $script:absentPrivilege) {
            Set-ItResult -Skipped -Because 'Every candidate privilege is present in the token.'
            return
        }

        {
            InModuleScope WindowsAccessControl -Parameters @{
                PrivilegeName = $script:absentPrivilege
            } {
                Invoke-WithWindowsPrivilege -Name $PrivilegeName -ScriptBlock { $true }
            }
        } | Should -Throw -ExpectedMessage "*$($script:absentPrivilege)*"
    }

    It 'Should scope SeSecurityPrivilege automatically for SACL commands' {
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-WithWindowsPrivilege -MockWith {
            & $ScriptBlock @ArgumentList
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'automatic-sacl.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = 'S-1-1-0'
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }

        Add-NTFSAuditRule @addParameters
        $getParameters = @{
            LiteralPath      = $testFile
            Account          = 'S-1-1-0'
            ExcludeInherited = $true
        }
        $result = Get-NTFSAuditRule @getParameters

        $result | Should -Not -BeNullOrEmpty
        $invokeParameters = @{
            ModuleName  = 'WindowsAccessControl'
            CommandName = 'Invoke-WithWindowsPrivilege'
            Times       = 2
            Exactly     = $false
        }
        Should -Invoke @invokeParameters
        Test-WindowsPrivilege -Name $script:scopePrivilege | Should -BeFalse
    }

    It 'Should scope SeRestorePrivilege automatically for an arbitrary owner' {
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-WithWindowsPrivilege -MockWith {
            $leases = @(
                foreach ($privilegeName in $Name) {
                    [WindowsAccessControl.NativeMethods]::AcquirePrivilege($privilegeName)
                }
            )
            try {
                & $ScriptBlock @ArgumentList
            } finally {
                foreach ($lease in $leases) {
                    $lease.Dispose()
                }
            }
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'automatic-owner.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $originalOwner = Get-NTFSItemOwner -LiteralPath $testFile
        $targetSid = if ($originalOwner.SID -eq 'S-1-5-32-544') {
            'S-1-5-32-545'
        } else {
            'S-1-1-0'
        }

        try {
            Set-NTFSItemOwner -LiteralPath $testFile -Account $targetSid -Confirm:$false

            (Get-NTFSItemOwner -LiteralPath $testFile).SID | Should -Be $targetSid
            $invokeParameters = @{
                ModuleName     = 'WindowsAccessControl'
                CommandName    = 'Invoke-WithWindowsPrivilege'
                Times          = 1
                Exactly        = $false
                ParameterFilter = { $Name -contains 'SeRestorePrivilege' }
            }
            Should -Invoke @invokeParameters
            Test-WindowsPrivilege -Name $script:restorePrivilege | Should -BeFalse
        } finally {
            Set-NTFSItemOwner -LiteralPath $testFile -Account $originalOwner.SID -Confirm:$false
        }
    }
}
