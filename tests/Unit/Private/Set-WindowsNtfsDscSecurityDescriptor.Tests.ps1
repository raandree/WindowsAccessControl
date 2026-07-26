BeforeDiscovery {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Set-WindowsNtfsDscSecurityDescriptor' -Tag 'Unit', 'WindowsOnly' {
    InModuleScope WindowsAccessControl {
        BeforeEach {
            $script:testPath = Join-Path $TestDrive 'dsc-exact.txt'
            Set-Content -LiteralPath $script:testPath -Value 'test'
            $script:testItem = Get-Item -LiteralPath $script:testPath
            $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
            $script:testSecurity.SetSecurityDescriptorSddlForm(
                'O:SYG:SYD:(A;;FR;;;WD)S:(AU;FA;FR;;;WD)'
            )
            Mock Resolve-NTFSPath { $script:testItem }
            Mock Get-NTFSSecurityDescriptorForItem { $script:testSecurity }
            Mock Invoke-NTFSSecurityDescriptorPersistence
        }

        It 'Should persist only a selected DACL and its protection state' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections Access `
                -Sddl 'D:P(A;;FW;;;WD)'

            $script:testSecurity.GetSecurityDescriptorSddlForm('Access') |
                Should -BeExactly 'D:P(A;;FW;;;WD)'
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 1 `
                -ParameterFilter {
                    $Sections -eq 'Access' -and
                        $ProtectionSection -eq 'Access'
                }
        }

        It 'Should persist only a selected SACL and its protection state' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections Audit `
                -Sddl 'S:P(AU;SA;FW;;;WD)'

            $script:testSecurity.GetSecurityDescriptorSddlForm('Audit') |
                Should -BeExactly 'S:P(AU;SA;FW;;;WD)'
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 1 `
                -ParameterFilter {
                    $Sections -eq 'Audit' -and
                        $ProtectionSection -eq 'Audit'
                }
        }

        It 'Should persist owner state without an ACL protection write' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections Owner `
                -Sddl 'O:BA'

            $script:testSecurity.GetSecurityDescriptorSddlForm('Owner') |
                Should -BeExactly 'O:BA'
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 1 `
                -ParameterFilter {
                    $Sections -eq 'Owner' -and -not $ProtectionSection
                }
        }

        It 'Should persist selected DACL and SACL protection together' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections All `
                -Sddl 'O:BAG:BAD:P(A;;FW;;;WD)S:P(AU;SA;FW;;;WD)'

            $script:testSecurity.GetSecurityDescriptorSddlForm('Access') |
                Should -BeExactly 'D:P(A;;FW;;;WD)'
            $script:testSecurity.GetSecurityDescriptorSddlForm('Audit') |
                Should -BeExactly 'S:P(AU;SA;FW;;;WD)'
            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 1 `
                -ParameterFilter {
                    $Sections -eq 'All' -and
                        $ProtectionSection -eq 'All'
                }
        }

        It 'Should not request SACL protection when the selected SACL is absent' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections All `
                -Sddl 'O:BAG:BAD:P(A;;FW;;;WD)S:NO_ACCESS_CONTROL'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 1 `
                -ParameterFilter {
                    $Sections -eq 'All' -and
                        $ProtectionSection -eq 'Access'
                }
        }

        It 'Should skip persistence when the selected state is identical' {
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $script:testPath `
                -Sections Access `
                -Sddl 'D:(A;;FR;;;WD)'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 0
        }

        It 'Should reject a selected owner that is omitted from SDDL' {
            {
                Set-WindowsNtfsDscSecurityDescriptor `
                    -Path $script:testPath `
                    -Sections Owner `
                    -Sddl 'G:SY'
            } | Should -Throw -ExpectedMessage '*selected owner*'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 0
        }

        It 'Should reject a selected primary group that is omitted from SDDL' {
            {
                Set-WindowsNtfsDscSecurityDescriptor `
                    -Path $script:testPath `
                    -Sections Group `
                    -Sddl 'O:SY'
            } | Should -Throw -ExpectedMessage '*selected primary group*'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 0
        }

        It 'Should reject a selected null DACL' {
            {
                Set-WindowsNtfsDscSecurityDescriptor `
                    -Path $script:testPath `
                    -Sections Access `
                    -Sddl 'D:NO_ACCESS_CONTROL'
            } | Should -Throw -ExpectedMessage '*selected non-null DACL*'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 0
        }

        It 'Should reject a selected SACL that is not represented' {
            {
                Set-WindowsNtfsDscSecurityDescriptor `
                    -Path $script:testPath `
                    -Sections Audit `
                    -Sddl 'D:(A;;FR;;;WD)'
            } | Should -Throw -ExpectedMessage '*selected SACL*'

            Should -Invoke Invoke-NTFSSecurityDescriptorPersistence `
                -Exactly `
                -Times 0
        }
    }
}
