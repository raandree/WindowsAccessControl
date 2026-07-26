BeforeDiscovery {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
    & $script:module {
        if (-not (Get-Command -Name Set-WindowsNtfsDscSecurityDescriptor `
                -ErrorAction SilentlyContinue)) {
            function script:Set-WindowsNtfsDscSecurityDescriptor {
                throw 'The test must mock this adapter.'
            }
        }
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Windows access control DSC security descriptor adapters' -Tag 'Unit', 'WindowsOnly' {
    InModuleScope WindowsAccessControl {
        BeforeEach {
            $script:descriptor = [pscustomobject]@{
                Sddl = 'D:(A;;0x00000001;;;WD)'
            }
            Mock Get-NTFSItemSecurityDescriptor { $script:descriptor }
            Mock Get-RegistryKeySecurityDescriptor { $script:descriptor }
            Mock Get-ServiceSecurityDescriptor { $script:descriptor }
            Mock Get-ProcessSecurityDescriptor { $script:descriptor }
            Mock Set-WindowsNtfsDscSecurityDescriptor
            Mock Set-RegistryKeySecurityDescriptor
            Mock Set-ServiceSecurityDescriptor
            Mock Set-ProcessSecurityDescriptor
        }

        It 'Should route a filesystem descriptor read' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily FileSystem `
                -Target 'C:\Data' `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-NTFSItemSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $LiteralPath -eq 'C:\Data' -and
                        $Sections -eq 'Access'
                }
        }

        It 'Should route a registry descriptor read with its view' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily RegistryKey `
                -Target 'HKLM:\Software\Contoso' `
                -RegistryView Registry64 `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-RegistryKeySecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Path -eq 'HKLM:\Software\Contoso' -and
                        $RegistryView -eq 'Registry64' -and
                        $Sections -eq 'Access'
                }
        }

        It 'Should route a named service descriptor read' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily Service `
                -Target BITS `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-ServiceSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Name -eq 'BITS' -and -not $ServiceControlManager
                }
        }

        It 'Should route a Service Control Manager descriptor read' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ServiceControlManager `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-ServiceSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter { $ServiceControlManager }
        }

        It 'Should route a pinned process descriptor read' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily Process `
                -ProcessId 42 `
                -CreationTimeFileTime 123456789 `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-ProcessSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $InputObject.ProcessId -eq 42 -and
                        $InputObject.CreationTimeFileTime -eq 123456789
                }
        }

        It 'Should route a filesystem descriptor write' {
            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily FileSystem `
                -Target 'C:\Data' `
                -Sections Access `
                -Sddl 'D:(A;;0x00000001;;;WD)'

            Should -Invoke Set-WindowsNtfsDscSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Path -eq 'C:\Data' -and $Sections -eq 'Access'
                }
        }

        It 'Should route a registry descriptor write without confirmation' {
            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily RegistryKey `
                -Target 'HKLM:\Software\Contoso' `
                -RegistryView Registry32 `
                -Sections Access `
                -Sddl 'D:(A;;0x00000001;;;WD)'

            Should -Invoke Set-RegistryKeySecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Path -eq 'HKLM:\Software\Contoso' -and
                        $RegistryView -eq 'Registry32' -and
                        $Confirm -eq $false
                }
        }

        It 'Should route a named service descriptor write without confirmation' {
            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily Service `
                -Target BITS `
                -Sections Access `
                -Sddl 'D:(A;;0x00000001;;;WD)'

            Should -Invoke Set-ServiceSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Name -eq 'BITS' -and
                        -not $ServiceControlManager -and
                        $Confirm -eq $false
                }
        }

        It 'Should route a Service Control Manager descriptor write without confirmation' {
            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ServiceControlManager `
                -Sections Access `
                -Sddl 'D:(A;;0x00000001;;;WD)'

            Should -Invoke Set-ServiceSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $ServiceControlManager -and $Confirm -eq $false
                }
        }

        It 'Should route a pinned process descriptor write without confirmation' {
            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily Process `
                -ProcessId 42 `
                -CreationTimeFileTime 123456789 `
                -Sections Access `
                -Sddl 'D:(A;;0x00000001;;;WD)'

            Should -Invoke Set-ProcessSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $InputObject.ProcessId -eq 42 -and
                        $InputObject.CreationTimeFileTime -eq 123456789 -and
                        $Confirm -eq $false
                }
        }
    }
}
