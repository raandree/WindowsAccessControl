BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    function Get-TestRegistryDescriptor {
        param(
            [string]$Sddl = 'O:BAG:BAD:(A;;KA;;;SY)',

            [string]$Sections = 'Access'
        )

        InModuleScope -ModuleName WindowsAccessControl -Parameters @{
            Sddl     = $Sddl
            Sections = $Sections
        } -ScriptBlock {
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
            $bytes = [byte[]]::new($raw.BinaryLength)
            $raw.GetBinaryForm($bytes, 0)
            $target = [pscustomobject]@{
                ObjectType       = 'RegistryKey'
                Path             = 'HKCU:\Software\WacUnitTest'
                NativePath       = 'CURRENT_USER\Software\WacUnitTest'
                NativeObjectType = 4
                RegistryView     = 'Default'
                CanonicalTarget  = 'RegistryKey:Default:CURRENT_USER\SOFTWARE\WACUNITTEST'
            }
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections ([WindowsSecurityDescriptorSection]$Sections) `
                -SecurityDescriptor $bytes `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
        }
    }
}

Describe 'Registry descriptor-aware mutators' -Tag 'Unit', 'WindowsOnly' {
    Context 'Command contract' {
        It 'Should expose a SecurityDescriptor parameter set on <_>' -ForEach @(
            'Add-RegistryKeyAccessRule'
            'Set-RegistryKeyAccessRule'
            'Remove-RegistryKeyAccessRule'
            'Clear-RegistryKeyAccessRule'
            'Add-RegistryKeyAuditRule'
            'Set-RegistryKeyAuditRule'
            'Remove-RegistryKeyAuditRule'
            'Clear-RegistryKeyAuditRule'
            'Enable-RegistryKeyInheritance'
            'Disable-RegistryKeyInheritance'
            'Set-RegistryKeySecurityDescriptor'
        ) {
            $command = Get-Command -Name $_ -Module WindowsAccessControl -ErrorAction Stop

            $command.Parameters.ContainsKey('SecurityDescriptor') | Should -BeTrue
            $command.ParameterSets.Name | Should -Contain 'SecurityDescriptor'
        }

        It 'Should record a concurrency token when a descriptor is built' {
            $descriptor = Get-TestRegistryDescriptor

            $descriptor.ConcurrencyToken | Should -Match '^[0-9A-F]{64}$'
        }

        It 'Should bind a piped descriptor to the SecurityDescriptor set on <_>' -ForEach @(
            'Add-RegistryKeyAccessRule'
            'Set-RegistryKeyAccessRule'
            'Clear-RegistryKeyAccessRule'
            'Enable-RegistryKeyInheritance'
            'Disable-RegistryKeyInheritance'
            'Set-RegistryKeySecurityDescriptor'
        ) {
            $command = Get-Command -Name $_ -Module WindowsAccessControl -ErrorAction Stop
            $descriptorParameter = $command.Parameters['SecurityDescriptor']
            $pipelineSets = @(
                $descriptorParameter.Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    Where-Object { $_.ValueFromPipeline }
            )

            $command.DefaultParameterSet | Should -Be 'SecurityDescriptor'
            $pipelineSets | Should -Not -BeNullOrEmpty
            $descriptorParameter.Attributes.TypeId.Name |
                Should -Contain 'PSTypeNameAttribute'
        }
    }

    Context 'Access rule staging' {
        It 'Should stage an added access rule and return the same descriptor' {
            $descriptor = Get-TestRegistryDescriptor

            $result = $descriptor | Add-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey

            [object]::ReferenceEquals($result, $descriptor) | Should -BeTrue
            $descriptor.Sddl | Should -Match ';WD\)'
        }

        It 'Should replace matching access rules in memory' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;;KR;;;WD)'

            $null = $descriptor | Set-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights FullControl

            ([regex]::Matches($descriptor.Sddl, ';WD\)')).Count | Should -Be 1
            $descriptor.Sddl | Should -Match 'KA;;;WD\)'
        }

        It 'Should clear explicit access rules in memory' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;WD)'

            $null = $descriptor | Clear-RegistryKeyAccessRule

            $descriptor.Sddl | Should -Not -Match ';WD\)'
            $descriptor.Sddl | Should -Not -Match ';SY\)'
        }

        It 'Should clear only the selected account in memory' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;WD)'

            $null = $descriptor | Clear-RegistryKeyAccessRule -Account 'S-1-1-0'

            $descriptor.Sddl | Should -Not -Match ';WD\)'
            $descriptor.Sddl | Should -Match ';SY\)'
        }

        It 'Should not write to the target while staging' {
            InModuleScope WindowsAccessControl {
                Mock Set-WindowsNamedSecurityDescriptor
            }
            $descriptor = Get-TestRegistryDescriptor

            $null = $descriptor | Add-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey

            InModuleScope WindowsAccessControl {
                Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 0 -Exactly
            }
        }

        It 'Should refresh the projection without refreshing the token while staging' {
            $descriptor = Get-TestRegistryDescriptor
            $readToken = $descriptor.ConcurrencyToken

            $null = $descriptor | Add-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey

            $descriptor.Sddl | Should -Match ';WD\)'
            $descriptor.ConcurrencyToken | Should -BeExactly $readToken
        }
    }

    Context 'Audit rule staging' {
        It 'Should stage an added audit rule in memory' {
            $descriptor = Get-TestRegistryDescriptor `
                -Sddl 'O:BAG:BAD:(A;;KA;;;SY)S:(AU;SA;KA;;;SY)' `
                -Sections 'Audit'

            $null = $descriptor | Add-RegistryKeyAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights SetValue `
                -AuditFlags Failure

            $descriptor.Sddl | Should -Match 'S:.*;WD\)'
        }

        It 'Should clear explicit audit rules in memory' {
            $descriptor = Get-TestRegistryDescriptor `
                -Sddl 'O:BAG:BAD:(A;;KA;;;SY)S:(AU;SA;KA;;;SY)' `
                -Sections 'Audit'

            $null = $descriptor | Clear-RegistryKeyAuditRule

            $descriptor.Sddl | Should -Not -Match 'AU;'
        }
    }

    Context 'Inheritance-scope-sensitive duplicate detection' {
        BeforeAll {
            function Get-EveryoneAce {
                param(
                    [Parameter(Mandatory)]
                    [string]$Sddl,

                    [Parameter()]
                    [switch]$Audit
                )

                $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
                $acl = if ($Audit) { $raw.SystemAcl } else { $raw.DiscretionaryAcl }
                $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')

                @($acl | Where-Object { $_.SecurityIdentifier -eq $everyone })
            }
        }

        It 'Should add an access ACE that differs only by inheritance scope' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;;KR;;;WD)'

            $null = $descriptor | Add-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey `
                -AppliesTo ThisKeyAndSubkeys

            $aces = Get-EveryoneAce -Sddl $descriptor.Sddl

            $aces.Count | Should -Be 2
            @($aces.AceFlags) | Should -Contain ([System.Security.AccessControl.AceFlags]::None)
            @($aces.AceFlags) |
                Should -Contain ([System.Security.AccessControl.AceFlags]::ContainerInherit)
        }

        It 'Should still suppress an access ACE with an identical inheritance scope' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;CI;KR;;;WD)'

            $null = $descriptor | Add-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey `
                -AppliesTo ThisKeyAndSubkeys

            (Get-EveryoneAce -Sddl $descriptor.Sddl).Count | Should -Be 1
        }

        It 'Should add an audit ACE that differs only by inheritance scope' {
            $descriptor = Get-TestRegistryDescriptor `
                -Sddl 'O:BAG:BAD:(A;;KA;;;SY)S:(AU;SA;KR;;;WD)' `
                -Sections 'Audit'

            $null = $descriptor | Add-RegistryKeyAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey `
                -AuditFlags Success `
                -AppliesTo ThisKeyAndSubkeys

            (Get-EveryoneAce -Sddl $descriptor.Sddl -Audit).Count | Should -Be 2
        }

        It 'Should still suppress an audit ACE with an identical inheritance scope' {
            $descriptor = Get-TestRegistryDescriptor `
                -Sddl 'O:BAG:BAD:(A;;KA;;;SY)S:(AU;CISA;KR;;;WD)' `
                -Sections 'Audit'

            $null = $descriptor | Add-RegistryKeyAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights ReadKey `
                -AuditFlags Success `
                -AppliesTo ThisKeyAndSubkeys

            (Get-EveryoneAce -Sddl $descriptor.Sddl -Audit).Count | Should -Be 1
        }

        It 'Should keep Set replacing an access rule across inheritance scopes' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;CI;KR;;;WD)'

            $null = $descriptor | Set-RegistryKeyAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights FullControl `
                -AppliesTo ThisKeyOnly

            $aces = Get-EveryoneAce -Sddl $descriptor.Sddl

            $aces.Count | Should -Be 1
            $aces[0].AceFlags | Should -Be ([System.Security.AccessControl.AceFlags]::None)
            $aces[0].AccessMask |
                Should -Be ([int][System.Security.AccessControl.RegistryRights]::FullControl)
        }

        It 'Should keep Clear removing an access rule across inheritance scopes' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:(A;CI;KR;;;WD)(A;;KA;;;SY)'

            $null = $descriptor | Clear-RegistryKeyAccessRule -Account 'S-1-1-0'

            (Get-EveryoneAce -Sddl $descriptor.Sddl).Count | Should -Be 0
        }
    }

    Context 'Inheritance staging' {
        It 'Should protect the selected ACL in memory' {
            $descriptor = Get-TestRegistryDescriptor

            $null = $descriptor | Disable-RegistryKeyInheritance -Section Access

            $descriptor.AccessRulesProtected | Should -BeTrue
        }

        It 'Should unprotect the selected ACL in memory' {
            $descriptor = Get-TestRegistryDescriptor -Sddl 'O:BAG:BAD:P(A;;KA;;;SY)'

            $null = $descriptor | Enable-RegistryKeyInheritance -Section Access

            $descriptor.AccessRulesProtected | Should -BeFalse
        }
    }

    Context 'Unloaded section rejection' {
        It 'Should reject an audit edit when the audit section was not loaded' {
            $descriptor = Get-TestRegistryDescriptor

            {
                $descriptor | Add-RegistryKeyAuditRule `
                    -Account 'S-1-1-0' `
                    -AccessRights SetValue `
                    -AuditFlags Success `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Audit section*'
        }

        It 'Should reject an access edit when the access section was not loaded' {
            $descriptor = Get-TestRegistryDescriptor `
                -Sddl 'O:BAG:BAD:(A;;KA;;;SY)S:(AU;SA;KA;;;SY)' `
                -Sections 'Audit'

            {
                $descriptor | Add-RegistryKeyAccessRule `
                    -Account 'S-1-1-0' `
                    -AccessRights ReadKey `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Access section*'
        }
    }

    Context 'Concurrency token' {
        It 'Should reject RequireUnchanged without a recorded token' {
            InModuleScope WindowsAccessControl {
                {
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken '' `
                        -CurrentToken 'ABC' `
                        -Target 'HKCU:\Software\WacUnitTest'
                } | Should -Throw -ExpectedMessage '*ConcurrencyToken*'
            }
        }

        It 'Should reject a changed token' {
            InModuleScope WindowsAccessControl {
                {
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken 'ABC' `
                        -CurrentToken 'DEF' `
                        -Target 'HKCU:\Software\WacUnitTest'
                } | Should -Throw -ExpectedMessage '*changed after they were read*'
            }
        }

        It 'Should accept an unchanged token' {
            InModuleScope WindowsAccessControl {
                {
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken 'ABC' `
                        -CurrentToken 'ABC' `
                        -Target 'HKCU:\Software\WacUnitTest'
                } | Should -Not -Throw
            }
        }
    }
}
