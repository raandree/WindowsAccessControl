BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Active Directory distinguished-name containment' -Tag 'Unit', 'WindowsOnly' {
    It 'Should classify <Case> using actual component boundaries' -ForEach @(
        @{
            Case = 'the base itself'
            Target = 'OU=Targets,DC=example,DC=test'
            Expected = $true
        }
        @{
            Case = 'a nested descendant with different casing'
            Target = 'CN=Child,OU=Nested,ou=targets,dc=EXAMPLE,dc=test'
            Expected = $true
        }
        @{
            Case = 'a sibling with a similar suffix'
            Target = 'CN=Child,OU=OtherTargets,DC=example,DC=test'
            Expected = $false
        }
        @{
            Case = 'an escaped comma impersonating the base separator'
            Target = 'CN=Spoof\,OU=Targets,DC=example,DC=test'
            Expected = $false
        }
        @{
            Case = 'an escaped separator inside an ancestor name'
            Target = 'CN=Child,OU=Spoof\,OU=Targets,DC=example,DC=test'
            Expected = $false
        }
        @{
            Case = 'an odd escape count before the apparent separator'
            Target = 'CN=Spoof\\\,OU=Targets,DC=example,DC=test'
            Expected = $false
        }
        @{
            Case = 'a real separator after an escaped backslash'
            Target = 'CN=Backslash\\,OU=Targets,DC=example,DC=test'
            Expected = $true
        }
        @{
            Case = 'a contained name with an escaped comma'
            Target = 'CN=Last\,First,OU=Targets,DC=example,DC=test'
            Expected = $true
        }
        @{
            Case = 'a contained name with a hex-escaped comma'
            Target = 'CN=Last\2cFirst,OU=Targets,DC=example,DC=test'
            Expected = $true
        }
        @{
            Case = 'a multi-valued name outside the base'
            Target = 'CN=Outside+OU=Targets,DC=example,DC=test'
            Expected = $false
        }
    ) {
        InModuleScope WindowsAccessControl -Parameters @{
            Target = $Target
            Expected = $Expected
        } {
            $parameters = @{
                DistinguishedName = $Target
                BaseDistinguishedName = 'OU=Targets,DC=example,DC=test'
            }
            Test-WindowsADDistinguishedNameWithinBase @parameters | Should -Be $Expected
        }
    }
}