BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Edit-RegistryKeySecurityDescriptor' -Tag 'Unit', 'WindowsOnly' {
    It 'Should export the bounded editing contract' {
        $command = Get-Command Edit-RegistryKeySecurityDescriptor `
            -Module WindowsAccessControl `
            -ErrorAction Stop

        foreach ($parameter in @(
            'Path',
            'Sections',
            'ScriptBlock',
            'ArgumentList',
            'RegistryView',
            'RequireUnchanged',
            'ThrottleLimit',
            'PassThru',
            'WhatIf'
        )) {
            $command.Parameters.ContainsKey($parameter) | Should -BeTrue
        }
    }

    It 'Should cap caller callbacks to sequential batch dispatch' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsRegistryCommandBatch

            Edit-RegistryKeySecurityDescriptor `
                -Path 'HKCU:\Software\One', 'HKCU:\Software\Two' `
                -ScriptBlock { param($Descriptor) $null = $Descriptor } `
                -ThrottleLimit 8

            Should -Invoke Invoke-WindowsRegistryCommandBatch `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $ThrottleLimit -eq 1 }
        }
    }

    It 'Should read and persist the selected descriptor exactly once' {
        InModuleScope WindowsAccessControl {
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                'O:BAG:BAD:(A;;KA;;;SY)'
            )
            $script:testBytes = [byte[]]::new($raw.BinaryLength)
            $raw.GetBinaryForm($script:testBytes, 0)
            Mock Get-WindowsNamedSecurityDescriptor { $script:testBytes }
            Mock Set-WindowsNamedSecurityDescriptor

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Edit-RegistryKeySecurityDescriptor `
                    -Path 'HKCU:\Software\WacUnitTest' `
                    -Sections Access `
                    -ScriptBlock {
                        param($Descriptor, $Account)
                        $Descriptor | Add-RegistryKeyAccessRule `
                            -Account $Account `
                            -AccessRights ReadKey | Out-Null
                    } `
                    -ArgumentList 'S-1-1-0' `
                    -PassThru `
                    -Confirm:$false
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.Sddl | Should -Match ';WD\)'
            Should -Invoke Get-WindowsNamedSecurityDescriptor -Times 1 -Exactly
            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 1 -Exactly
        }
    }

    It 'Should execute the callback but not persist under WhatIf' {
        InModuleScope WindowsAccessControl {
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                'O:BAG:BAD:(A;;KA;;;SY)'
            )
            $script:testBytes = [byte[]]::new($raw.BinaryLength)
            $raw.GetBinaryForm($script:testBytes, 0)
            $script:callbackRan = $false
            Mock Get-WindowsNamedSecurityDescriptor { $script:testBytes }
            Mock Set-WindowsNamedSecurityDescriptor

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Edit-RegistryKeySecurityDescriptor `
                    -Path 'HKCU:\Software\WacUnitTest' `
                    -Sections Access `
                    -ScriptBlock { $script:callbackRan = $true } `
                    -WhatIf
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $script:callbackRan | Should -BeTrue
            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 0 -Exactly
        }
    }

    It 'Should not persist when the callback fails or expands unloaded sections' {
        InModuleScope WindowsAccessControl {
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                'O:BAG:BAD:(A;;KA;;;SY)'
            )
            $script:testBytes = [byte[]]::new($raw.BinaryLength)
            $raw.GetBinaryForm($script:testBytes, 0)
            Mock Get-WindowsNamedSecurityDescriptor { $script:testBytes }
            Mock Set-WindowsNamedSecurityDescriptor

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                {
                    Edit-RegistryKeySecurityDescriptor `
                        -Path 'HKCU:\Software\WacUnitTest' `
                        -Sections Access `
                        -ScriptBlock { throw 'Expected callback failure.' } `
                        -Confirm:$false `
                        -ErrorAction Stop
                } | Should -Throw -ExpectedMessage '*Expected callback failure*'

                {
                    Edit-RegistryKeySecurityDescriptor `
                        -Path 'HKCU:\Software\WacUnitTest' `
                        -Sections Access `
                        -ScriptBlock {
                            param($Descriptor)
                            $Descriptor.Sections = [WindowsSecurityDescriptorSection]::All
                        } `
                        -Confirm:$false `
                        -ErrorAction Stop
                } | Should -Throw -ExpectedMessage '*sections that were not loaded*'
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 0 -Exactly
        }
    }
}
