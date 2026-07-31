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
            Mock Get-SmbShareSecurityDescriptor { $script:descriptor }
            Mock Get-ADObjectSecurityDescriptor { $script:descriptor }
            Mock Get-TaskFolderSecurityDescriptor { $script:descriptor }
            Mock Get-ScheduledTaskSecurityDescriptor { $script:descriptor }
            Mock Resolve-WindowsADServer { 'dc01.contoso.test' }
            Mock Set-WindowsNtfsDscSecurityDescriptor
            Mock Set-RegistryKeySecurityDescriptor
            Mock Set-ServiceSecurityDescriptor
            Mock Set-ProcessSecurityDescriptor
            Mock Set-SmbShareSecurityDescriptor
            Mock Set-ADObjectSecurityDescriptor
            Mock Set-TaskFolderSecurityDescriptor
            Mock Set-ScheduledTaskSecurityDescriptor
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

        It 'Should route an SMB share descriptor read and write' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily SmbShare `
                -Target 'WacLab$' `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-SmbShareSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter { $Name -eq 'WacLab$' }

            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily SmbShare `
                -Target 'WacLab$' `
                -Sections Access `
                -Sddl 'D:(A;;0x001200A9;;;WD)'

            Should -Invoke Set-SmbShareSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter { $Name -eq 'WacLab$' -and $Confirm -eq $false }
        }

        It 'Should route a directory descriptor read and write through a pinned server' {
            $distinguishedName = 'CN=Test,OU=Targets,DC=contoso,DC=test'
            $allowedBase = 'OU=Targets,DC=contoso,DC=test'

            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ADObject `
                -Target $distinguishedName `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-ADObjectSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Server -eq 'dc01.contoso.test' -and
                        $DistinguishedName -eq $distinguishedName
                }

            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ADObject `
                -Target $distinguishedName `
                -AllowedBaseDistinguishedName $allowedBase `
                -Sections Access `
                -Sddl 'D:(A;;0x00000010;;;WD)'

            Should -Invoke Set-ADObjectSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Server -eq 'dc01.contoso.test' -and
                        $AllowedBaseDistinguishedName -eq $allowedBase -and
                        $Confirm -eq $false
                }
        }

        It 'Should reject a non-access section for an enterprise family' {
            {
                Get-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily SmbShare `
                    -Target 'WacLab$' `
                    -Sections Owner
            } | Should -Throw '*access section*'

            {
                Set-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily ADObject `
                    -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                    -AllowedBaseDistinguishedName 'OU=Targets,DC=contoso,DC=test' `
                    -Sections 'Owner, Access' `
                    -Sddl 'D:(A;;0x00000010;;;WD)'
            } | Should -Throw '*access section*'
        }

        It 'Should require an allowed base before a directory descriptor write' {
            {
                Set-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily ADObject `
                    -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                    -Sections Access `
                    -Sddl 'D:(A;;0x00000010;;;WD)'
            } | Should -Throw '*AllowedBaseDistinguishedName*'
            Should -Invoke Set-ADObjectSecurityDescriptor -Exactly -Times 0
        }

        It 'Should re-assert a pinned object GUID before a directory write' {
            Mock Resolve-WindowsADObjectTarget {
                throw 'The Active Directory object GUID no longer matches the path-bound target.'
            }

            {
                Set-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily ADObject `
                    -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                    -AllowedBaseDistinguishedName 'OU=Targets,DC=contoso,DC=test' `
                    -ObjectGuid '2f1d6c4a-6b6f-4a0e-9d02-3a1f9f0a1234' `
                    -Sections Access `
                    -Sddl 'D:(A;;0x00000010;;;WD)'
            } | Should -Throw '*object GUID*'
            Should -Invoke Set-ADObjectSecurityDescriptor -Exactly -Times 0
        }

        It 'Should route a task-folder descriptor read and contained write' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily TaskFolder `
                -Target '\Operations' `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-TaskFolderSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter { $Path -eq '\Operations' }

            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily TaskFolder `
                -Target '\Operations' `
                -AllowedRootPath '\Operations' `
                -Sections Access `
                -Sddl 'D:(A;;0x00000021;;;WD)'

            Should -Invoke Set-TaskFolderSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Path -eq '\Operations' -and
                        $AllowedRootPath -eq '\Operations' -and
                        $Confirm -eq $false
                }
        }

        It 'Should route a registered-task descriptor read and contained write' {
            $result = Get-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ScheduledTask `
                -Target '\Operations' `
                -TaskName 'Cleanup' `
                -Sections Access

            $result | Should -Be $script:descriptor
            Should -Invoke Get-ScheduledTaskSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $TaskPath -eq '\Operations' -and $TaskName -eq 'Cleanup'
                }

            Set-WindowsAccessControlDscSecurityDescriptor `
                -ObjectFamily ScheduledTask `
                -Target '\Operations' `
                -TaskName 'Cleanup' `
                -AllowedRootPath '\Operations' `
                -Sections Access `
                -Sddl 'D:(A;;0x00000020;;;WD)'

            Should -Invoke Set-ScheduledTaskSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $TaskPath -eq '\Operations' -and
                        $TaskName -eq 'Cleanup' -and
                        $AllowedRootPath -eq '\Operations' -and
                        $Confirm -eq $false
                }
        }

        It 'Should require an allowed root path before a Task Scheduler descriptor write' {
            {
                Set-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily TaskFolder `
                    -Target '\Operations' `
                    -Sections Access `
                    -Sddl 'D:(A;;0x00000021;;;WD)'
            } | Should -Throw '*AllowedRootPath*'
            Should -Invoke Set-TaskFolderSecurityDescriptor -Exactly -Times 0
        }

        It 'Should reject a non-access section for a Task Scheduler family' {
            {
                Get-WindowsAccessControlDscSecurityDescriptor `
                    -ObjectFamily TaskFolder `
                    -Target '\Operations' `
                    -Sections Owner
            } | Should -Throw '*access section*'
        }
    }
}
