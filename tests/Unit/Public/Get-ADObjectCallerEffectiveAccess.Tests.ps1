. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-ADObjectCallerEffectiveAccess' `
    -RequiredParameters @('Server', 'DistinguishedName', 'Credential', 'TimeoutSeconds', 'ThrottleLimit') `
    -SupportsShouldProcess $false

BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-ADObjectCallerEffectiveAccess behavior' -Tag 'Unit', 'WindowsOnly' {
    It 'Should not expose an account parameter that the directory cannot answer' {
        $command = Get-Command -Name 'Get-ADObjectCallerEffectiveAccess' `
            -Module 'WindowsAccessControl' -ErrorAction Stop

        $command.Parameters.ContainsKey('Account') | Should -BeFalse
    }

    It 'Should report one caller-scoped result per target from the constructed attributes' {
        $results = InModuleScope WindowsAccessControl {
            Mock New-WindowsADConnection {
                [System.DirectoryServices.Protocols.LdapConnection]::new(
                    [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                        'dc01.example.test',
                        389
                    )
                )
            }
            Mock Resolve-WindowsADObjectTarget {
                param($DistinguishedName)
                [pscustomobject]@{
                    Server = 'dc01.example.test'
                    DistinguishedName = $DistinguishedName
                    ObjectGuid = [guid]::Empty
                    CanonicalTarget = "ADObject:DC01.EXAMPLE.TEST:$DistinguishedName"
                }
            }
            Mock Get-WindowsADEffectiveAccessRecord {
                [pscustomobject]@{
                    WritableAttribute = @('displayName', 'description')
                    CreatableChildClass = @('user')
                    SDRightsEffective = 7
                }
            }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Get-ADObjectCallerEffectiveAccess `
                    -Server 'dc01.example.test' `
                    -DistinguishedName 'OU=One,OU=Lab,DC=example,DC=test',
                        'OU=Two,OU=Lab,DC=example,DC=test' `
                    -ThrottleLimit 1
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $results.Count | Should -Be 2
        $results[0].PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.ADObjectCallerEffectiveAccess'
        $results[0].DistinguishedName | Should -BeExactly 'OU=One,OU=Lab,DC=example,DC=test'
        $results[1].DistinguishedName | Should -BeExactly 'OU=Two,OU=Lab,DC=example,DC=test'
        $results[0].Account | Should -Not -BeNullOrEmpty
        $results[0].AuthorizationContext | Should -BeExactly 'DomainControllerCallerScoped'
    }

    It 'Should report the credential user as the evaluated identity' {
        $result = InModuleScope WindowsAccessControl {
            Mock New-WindowsADConnection {
                [System.DirectoryServices.Protocols.LdapConnection]::new(
                    [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                        'dc01.example.test',
                        389
                    )
                )
            }
            Mock Resolve-WindowsADObjectTarget {
                param($DistinguishedName)
                [pscustomobject]@{
                    Server = 'dc01.example.test'
                    DistinguishedName = $DistinguishedName
                    ObjectGuid = [guid]::Empty
                    CanonicalTarget = "ADObject:DC01.EXAMPLE.TEST:$DistinguishedName"
                }
            }
            Mock Get-WindowsADEffectiveAccessRecord {
                [pscustomobject]@{
                    WritableAttribute = @()
                    CreatableChildClass = @()
                    SDRightsEffective = 0
                }
            }
            $password = [Security.SecureString]::new()
            foreach ($character in 'placeholder'.ToCharArray()) {
                $password.AppendChar($character)
            }
            $credential = [pscredential]::new('CONTOSO\analyst', $password)

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Get-ADObjectCallerEffectiveAccess `
                    -Server 'dc01.example.test' `
                    -DistinguishedName 'OU=Lab,DC=example,DC=test' `
                    -Credential $credential `
                    -ThrottleLimit 1
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $result.Account | Should -BeExactly 'CONTOSO\analyst'
    }
}

Describe 'Caller-scoped directory result conversion' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $script:target = [pscustomobject]@{
            Server = 'dc01.example.test'
            DistinguishedName = 'OU=Lab,DC=example,DC=test'
            ObjectGuid = [guid]'11111111-2222-3333-4444-555555555555'
            CanonicalTarget = 'ADObject:DC01.EXAMPLE.TEST:GUID'
        }
    }

    It 'Should sort both name lists and report their counts' {
        $result = InModuleScope WindowsAccessControl -Parameters @{
            Target = $script:target
        } {
            param($Target)
            ConvertTo-WindowsADEffectiveAccessObject `
                -Target $Target `
                -Account 'CONTOSO\alice' `
                -Record ([pscustomobject]@{
                    WritableAttribute = @('displayName', 'description', 'cn')
                    CreatableChildClass = @('user', 'group')
                    SDRightsEffective = 4
                })
        }

        $result.WritableAttribute | Should -Be @('cn', 'description', 'displayName')
        $result.WritableAttributeCount | Should -Be 3
        $result.CreatableChildClass | Should -Be @('group', 'user')
        $result.CreatableChildClassCount | Should -Be 2
    }

    It 'Should map the <SDRights> mask onto <Sections> descriptor sections' -ForEach @(
        @{ SDRights = 0; Sections = 0 }
        @{ SDRights = 4; Sections = 4 }
        @{ SDRights = 15; Sections = 15 }
    ) {
        $result = InModuleScope WindowsAccessControl -Parameters @{
            Target = $script:target
            SDRights = $SDRights
        } {
            param($Target, $SDRights)
            ConvertTo-WindowsADEffectiveAccessObject `
                -Target $Target `
                -Account 'CONTOSO\alice' `
                -Record ([pscustomobject]@{
                    WritableAttribute = @()
                    CreatableChildClass = @()
                    SDRightsEffective = $SDRights
                })
        }

        $result.SDRightsEffective | Should -Be $SDRights
        [int]$result.WritableDescriptorSection | Should -Be $Sections
    }

    It 'Should report an empty result rather than inventing one' {
        $result = InModuleScope WindowsAccessControl -Parameters @{
            Target = $script:target
        } {
            param($Target)
            ConvertTo-WindowsADEffectiveAccessObject `
                -Target $Target `
                -Account 'CONTOSO\alice' `
                -Record ([pscustomobject]@{
                    WritableAttribute = @()
                    CreatableChildClass = @()
                    SDRightsEffective = 0
                })
        }

        $result.WritableAttributeCount | Should -Be 0
        $result.CreatableChildClassCount | Should -Be 0
        [int]$result.WritableDescriptorSection | Should -Be 0
        $result.CanonicalTarget | Should -BeExactly 'ADObject:DC01.EXAMPLE.TEST:GUID'
        $result.AuthorizationContext | Should -BeExactly 'DomainControllerCallerScoped'
    }
}
