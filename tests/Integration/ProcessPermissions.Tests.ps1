BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:testSid = 'S-1-1-0'
    $script:childProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    $script:isAdministrator = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $script:initialPrivilegeState = @{}
    foreach ($privilegeName in 'SeSecurityPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege') {
        $script:initialPrivilegeState[$privilegeName] =
            Test-WindowsPrivilege -Name $privilegeName
    }

    function Start-WindowsAccessControlTestProcess {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This private Pester fixture starts a controlled child process.'
        )]
        [CmdletBinding()]
        param()

        $powershellPath = Join-Path $env:SystemRoot (
            'System32\WindowsPowerShell\v1.0\powershell.exe'
        )
        $process = Start-Process -FilePath $powershellPath `
            -ArgumentList '-NoProfile', '-NonInteractive', '-Command', `
                '$null = ''WacProcessTest''; Start-Sleep -Seconds 120' `
            -WindowStyle Hidden -PassThru
        $null = $process.StartTime
        $script:childProcesses.Add($process)
        $script:process = $process
    }

    function Stop-WindowsAccessControlTestProcess {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This private Pester fixture stops its controlled child process.'
        )]
        [CmdletBinding()]
        param()

        if ($script:process) {
            try {
                if (-not $script:process.HasExited) {
                    $script:process.Kill()
                    $script:process.WaitForExit()
                }
            } finally {
                $null = $script:childProcesses.Remove($script:process)
                $script:process.Dispose()
                $script:process = $null
            }
        }
    }
}

AfterAll {
    foreach ($process in $script:childProcesses) {
        try {
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
        } finally {
            $process.Dispose()
        }
    }
    foreach ($privilegeName in $script:initialPrivilegeState.Keys) {
        Test-WindowsPrivilege -Name $privilegeName |
            Should -Be $script:initialPrivilegeState[$privilegeName]
    }
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Process security descriptors' -Tag 'Integration', 'WindowsOnly' {
    BeforeEach {
        Start-WindowsAccessControlTestProcess
    }

    AfterEach {
        Stop-WindowsAccessControlTestProcess
    }

    It 'Get-ProcessSecurityDescriptor should accept a Process pipeline object' {
        $result = $script:process | Get-ProcessSecurityDescriptor -Sections Access

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.ProcessSecurityDescriptor'
        $result.ObjectType | Should -Be 'Process'
        $result.ProcessId | Should -Be $script:process.Id
        $result.CreationTimeFileTime | Should -Be $script:process.StartTime.ToFileTimeUtc()
        $result.BinarySecurityDescriptor.Length | Should -BeGreaterThan 0
    }

    It 'Set-ProcessSecurityDescriptor should round-trip one pinned DACL and honor WhatIf' {
        $before = Get-ProcessSecurityDescriptor -ProcessId $script:process.Id -Sections Access

        Set-ProcessSecurityDescriptor -InputObject $before -Sddl $before.Sddl `
            -Sections Access -Confirm:$false
        Set-ProcessSecurityDescriptor -InputObject $before `
            -Sddl 'D:(A;;GR;;;WD)' -Sections Access -WhatIf

        (Get-ProcessSecurityDescriptor -InputObject $before -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }

    It 'Module output should reject a stale process creation identity' {
        $target = Get-ProcessSecurityDescriptor -ProcessId $script:process.Id -Sections Access
        $target.CreationTimeFileTime++

        {
            $target | Get-ProcessSecurityDescriptor `
                -Sections Access `
                -ErrorAction Stop
        } |
            Should -Throw -ExpectedMessage '*creation identity*'
    }

    It 'Caller-owned process handles should remain open and reusable' {
        $handle = $script:process.Handle

        $first = Get-ProcessSecurityDescriptor -Handle $handle -Sections Access
        $second = $first | Get-ProcessSecurityDescriptor -Sections Access
        Set-ProcessSecurityDescriptor -Handle $handle -Sddl $first.Sddl `
            -Sections Access -Confirm:$false

        $first.Handle | Should -Be $handle
        $second.Sddl | Should -BeExactly $first.Sddl
        $script:process.HasExited | Should -BeFalse
    }

    It 'Process target validation should reject PID zero and missing creation identity' {
        { Get-ProcessSecurityDescriptor -ProcessId 0 -Sections Access } |
            Should -Throw
        $invalid = [pscustomobject]@{
            ObjectType   = 'Process'
            ProcessId    = $script:process.Id
            ProcessName  = $script:process.ProcessName
        }
        { $invalid | Get-ProcessSecurityDescriptor -Sections Access } |
            Should -Throw -ExpectedMessage '*creation identity*'
    }
}

Describe 'Process access rules' -Tag 'Integration', 'WindowsOnly' {
    BeforeEach {
        Start-WindowsAccessControlTestProcess
    }

    AfterEach {
        Stop-WindowsAccessControlTestProcess
    }

    It 'Add-ProcessAccessRule and Get-ProcessAccessRule should persist typed process rights' {
        Add-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -Confirm:$false

        $result = Get-ProcessAccessRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited

        $result | Should -HaveCount 1
        $result.AccessRights | Should -Be ([WindowsProcessRights]::QueryLimitedInformation)
        $result.AccessMask | Should -BeOfType ([uint64])
        $result.AppliesTo | Should -BeNullOrEmpty
    }

    It 'Set-ProcessAccessRule should preserve the opposite access qualifier' {
        Add-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Terminate -AccessControlType Deny -Confirm:$false
        Add-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -Confirm:$false

        Set-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Synchronize -Confirm:$false

        $rules = @(Get-ProcessAccessRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited)
        $rules | Should -HaveCount 2
        ($rules | Where-Object AccessControlType -EQ Allow).AccessRights |
            Should -Be ([WindowsProcessRights]::Synchronize)
        ($rules | Where-Object AccessControlType -EQ Deny).AccessRights |
            Should -Be ([WindowsProcessRights]::Terminate)
    }

    It 'Remove-ProcessAccessRule should remove an exact pipeline rule' {
        Add-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -Confirm:$false
        $rule = Get-ProcessAccessRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited

        $rule | Remove-ProcessAccessRule -Confirm:$false

        Get-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Clear-ProcessAccessRule should remove selected explicit account rules' {
        Add-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -Confirm:$false

        Clear-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -Confirm:$false

        Get-ProcessAccessRule -ProcessId $script:process.Id -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Caller-owned handles should support access mutation without being closed' {
        $handle = $script:process.Handle

        Add-ProcessAccessRule -Handle $handle -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -Confirm:$false
        Get-ProcessAccessRule -Handle $handle -Account $script:testSid `
            -ExcludeInherited | Should -HaveCount 1
        Clear-ProcessAccessRule -Handle $handle -Account $script:testSid `
            -Confirm:$false

        Get-ProcessAccessRule -Handle $handle -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
        $script:process.HasExited | Should -BeFalse
    }
}

Describe 'Process audit rules' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        Start-WindowsAccessControlTestProcess
    }

    AfterEach {
        Stop-WindowsAccessControlTestProcess
    }

    It 'Add-ProcessAuditRule and Get-ProcessAuditRule should persist a SACL rule' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Process SACL operations require elevation.'
            return
        }
        Add-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Terminate -AuditFlags Failure -Confirm:$false

        $result = @(Get-ProcessAuditRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited | Where-Object {
                $_.AccessRights -eq [WindowsProcessRights]::Terminate
            })

        $result | Should -HaveCount 1
        $result.AuditFlags | Should -Be 'Failure'
    }

    It 'Set-ProcessAuditRule should preserve opposite audit flags' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Process SACL operations require elevation.'
            return
        }
        Add-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -AuditFlags Success -Confirm:$false
        Add-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights QueryLimitedInformation -AuditFlags Failure -Confirm:$false

        Set-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Terminate -AuditFlags Failure -Confirm:$false

        $rules = @(Get-ProcessAuditRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited)
        ($rules | Where-Object AuditFlags -EQ Success).AccessRights |
            Should -Be ([WindowsProcessRights]::QueryLimitedInformation)
        ($rules | Where-Object AuditFlags -EQ Failure).AccessRights |
            Should -Contain ([WindowsProcessRights]::Terminate)
    }

    It 'Remove-ProcessAuditRule should remove an exact pipeline rule' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Process SACL operations require elevation.'
            return
        }
        Add-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Terminate -AuditFlags Failure -Confirm:$false
        $rule = Get-ProcessAuditRule -ProcessId $script:process.Id `
            -Account $script:testSid -ExcludeInherited | Where-Object {
                $_.AccessRights -eq [WindowsProcessRights]::Terminate
            }

        $rule | Remove-ProcessAuditRule -Confirm:$false

        Get-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ExcludeInherited | Where-Object {
                $_.AccessRights -eq [WindowsProcessRights]::Terminate
            } | Should -BeNullOrEmpty
    }

    It 'Clear-ProcessAuditRule should remove selected explicit account rules' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Process SACL operations require elevation.'
            return
        }
        Add-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ProcessRights Terminate -AuditFlags Failure -Confirm:$false

        Clear-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -Confirm:$false

        Get-ProcessAuditRule -ProcessId $script:process.Id -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }
}
