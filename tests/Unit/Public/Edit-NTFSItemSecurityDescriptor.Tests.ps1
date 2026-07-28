BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Edit-NTFSItemSecurityDescriptor' -Tag 'Unit', 'WindowsOnly' {
    It 'Should export the bounded editing contract' {
        $command = Get-Command Edit-NTFSItemSecurityDescriptor `
            -Module WindowsAccessControl `
            -ErrorAction Stop

        foreach ($parameter in @(
            'Path',
            'LiteralPath',
            'Sections',
            'ScriptBlock',
            'ArgumentList',
            'ThrottleLimit',
            'PassThru',
            'WhatIf'
        )) {
            $command.Parameters.ContainsKey($parameter) | Should -BeTrue
        }
    }

    It 'Should cap caller callbacks to sequential batch dispatch' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsNtfsCommandBatch

            Edit-NTFSItemSecurityDescriptor `
                -LiteralPath 'C:\Data\one.txt', 'C:\Data\two.txt' `
                -ScriptBlock { param($Descriptor) $null = $Descriptor } `
                -ThrottleLimit 8

            Should -Invoke Invoke-WindowsNtfsCommandBatch `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $ThrottleLimit -eq 1 }
        }
    }

    It 'Should read and persist the selected descriptor exactly once' {
        InModuleScope WindowsAccessControl {
            $script:testItem = [IO.FileInfo]::new('C:\Data\edit.txt')
            $script:testSecurity = [Security.AccessControl.FileSecurity]::new()
            $script:testDescriptor = [pscustomobject]@{
                Path = $script:testItem.FullName
                ItemType = 'File'
                Sections = [Security.AccessControl.AccessControlSections]::Access
                NativeSecurity = $script:testSecurity
                Edited = $false
            }
            $script:testDescriptor.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.SecurityDescriptor'
            )
            Mock Resolve-NTFSPath { $script:testItem }
            Mock Get-NTFSSecurityDescriptorForItem { $script:testSecurity }
            Mock ConvertTo-NTFSSecurityDescriptorObject { $script:testDescriptor }
            Mock Invoke-NTFSSecurityDescriptorPersistence

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Edit-NTFSItemSecurityDescriptor `
                    -LiteralPath $script:testItem.FullName `
                    -Sections Access `
                    -ScriptBlock {
                        param($Descriptor, $Marker)
                        $Descriptor.Edited = $Marker
                    } `
                    -ArgumentList $true `
                    -PassThru `
                    -Confirm:$false
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.Edited | Should -BeTrue
            Should -Invoke Get-NTFSSecurityDescriptorForItem -Times 1 -Exactly
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $Sections -eq [Security.AccessControl.AccessControlSections]::Access -and
                        $ProtectionSection -eq 'Access'
                }
        }
    }

    It 'Should execute the callback but not persist under WhatIf' {
        InModuleScope WindowsAccessControl {
            $script:testItem = [IO.FileInfo]::new('C:\Data\whatif.txt')
            $script:testSecurity = [Security.AccessControl.FileSecurity]::new()
            $script:testDescriptor = [pscustomobject]@{
                Path = $script:testItem.FullName
                ItemType = 'File'
                Sections = [Security.AccessControl.AccessControlSections]::Access
                NativeSecurity = $script:testSecurity
                Edited = $false
            }
            $script:testDescriptor.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.SecurityDescriptor'
            )
            Mock Resolve-NTFSPath { $script:testItem }
            Mock Get-NTFSSecurityDescriptorForItem { $script:testSecurity }
            Mock ConvertTo-NTFSSecurityDescriptorObject { $script:testDescriptor }
            Mock Invoke-NTFSSecurityDescriptorPersistence

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Edit-NTFSItemSecurityDescriptor `
                    -LiteralPath $script:testItem.FullName `
                    -Sections Access `
                    -ScriptBlock { param($Descriptor) $Descriptor.Edited = $true } `
                    -WhatIf
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $script:testDescriptor.Edited | Should -BeTrue
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
        }
    }

    It 'Should not persist when the callback fails or expands unloaded sections' {
        InModuleScope WindowsAccessControl {
            $script:testItem = [IO.FileInfo]::new('C:\Data\failure.txt')
            $script:testSecurity = [Security.AccessControl.FileSecurity]::new()
            $script:testDescriptor = [pscustomobject]@{
                Path = $script:testItem.FullName
                ItemType = 'File'
                Sections = [Security.AccessControl.AccessControlSections]::Access
                NativeSecurity = $script:testSecurity
            }
            $script:testDescriptor.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.SecurityDescriptor'
            )
            Mock Resolve-NTFSPath { $script:testItem }
            Mock Get-NTFSSecurityDescriptorForItem { $script:testSecurity }
            Mock ConvertTo-NTFSSecurityDescriptorObject { $script:testDescriptor }
            Mock Invoke-NTFSSecurityDescriptorPersistence

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                {
                    Edit-NTFSItemSecurityDescriptor `
                        -LiteralPath $script:testItem.FullName `
                        -Sections Access `
                        -ScriptBlock { throw 'Expected edit failure.' } `
                        -Confirm:$false
                } | Should -Throw -ExpectedMessage '*Expected edit failure*'

                {
                    Edit-NTFSItemSecurityDescriptor `
                        -LiteralPath $script:testItem.FullName `
                        -Sections Access `
                        -ScriptBlock {
                            param($Descriptor)
                            $Descriptor.Sections = [Security.AccessControl.AccessControlSections]::All
                        } `
                        -Confirm:$false
                } | Should -Throw -ExpectedMessage '*sections that were not loaded*'
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
        }
    }
}