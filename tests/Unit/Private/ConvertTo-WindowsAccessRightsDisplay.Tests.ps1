BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl
}

Describe 'Access rights display' -Tag 'Unit', 'WindowsOnly' {
    It 'Should name the bits FileSystemRights cannot name in <Mask>' -ForEach @(
        @{ Mask = 0xE0010000L; Expected = 'Delete, GenericExecute, GenericWrite, GenericRead' }
        @{ Mask = 0x10000000L; Expected = 'GenericAll' }
        @{ Mask = 0x01000000L; Expected = 'AccessSystemSecurity' }
        @{ Mask = 0x02000000L; Expected = 'MaximumAllowed' }
        @{ Mask = 0x00000400L; Expected = '0x00000400' }
        @{ Mask = 0x80000400L; Expected = 'GenericRead, 0x00000400' }
    ) {
        $display = & $script:module {
            param($Mask)
            ConvertTo-WindowsAccessRightsDisplay `
                -AccessMask $Mask `
                -RightsType ([System.Security.AccessControl.FileSystemRights])
        } $Mask

        $display | Should -Be $Expected
    }

    It 'Should reuse the .NET rendering for the nameable mask <Mask>' -ForEach @(
        @{ Mask = 0x00000000L }
        @{ Mask = 0x00000004L }
        @{ Mask = 0x001301BFL }
        @{ Mask = 0x001200A9L }
        @{ Mask = 0x001F01FFL }
    ) {
        $display = & $script:module {
            param($Mask)
            ConvertTo-WindowsAccessRightsDisplay `
                -AccessMask $Mask `
                -RightsType ([System.Security.AccessControl.FileSystemRights])
        } $Mask

        $display | Should -Be ([string][System.Enum]::ToObject(
                [System.Security.AccessControl.FileSystemRights], $Mask))
    }

    It 'Should prefer the names an object family enum already defines' {
        $display = & $script:module {
            ConvertTo-WindowsAccessRightsDisplay `
                -AccessMask 0xE0000000L `
                -RightsType ([WindowsSmbShareRights])
        }

        $display | Should -Be 'GenericExecute, GenericWrite, GenericRead'
    }

    It 'Should keep repeated rights decompositions isolated by enum type' {
        $comparisons = @(& $script:module {
            $rightsTypes = @(
                [System.Security.AccessControl.FileSystemRights]
                [System.Security.AccessControl.RegistryRights]
                [WindowsServiceRights]
            )
            for ($iteration = 0; $iteration -lt 3; $iteration++) {
                foreach ($rightsType in $rightsTypes) {
                    $parameters = @{ AccessMask = 1; RightsType = $rightsType }
                    [pscustomobject]@{
                        Actual = ConvertTo-WindowsAccessRightsDisplay @parameters
                        Expected = [string][System.Enum]::ToObject($rightsType, 1)
                    }
                }
            }
        })

        $comparisons | Should -HaveCount 9
        foreach ($comparison in $comparisons) {
            $comparison.Actual | Should -BeExactly $comparison.Expected
        }
    }

    It 'Should still reject a non-enum type after an enum has been used' {
        {
            & $script:module {
                $null = ConvertTo-WindowsAccessRightsDisplay -AccessMask 1 -RightsType (
                    [System.Security.AccessControl.FileSystemRights]
                )
                ConvertTo-WindowsAccessRightsDisplay -AccessMask 1 -RightsType ([string])
            }
        } | Should -Throw -ExceptionType ([System.Management.Automation.MethodInvocationException])
    }

    It 'Should preserve every result when repeated masks exceed the display cache capacity' {
        $comparisons = @(& $script:module {
            $rightsType = [System.Security.AccessControl.FileSystemRights]
            for ($iteration = 0; $iteration -lt 2; $iteration++) {
                for ($mask = 0; $mask -lt 256; $mask++) {
                    $parameters = @{ AccessMask = $mask; RightsType = $rightsType }
                    [pscustomobject]@{
                        Actual = ConvertTo-WindowsAccessRightsDisplay @parameters
                        Expected = [string][System.Enum]::ToObject($rightsType, $mask)
                    }
                }
            }
        })

        $comparisons | Should -HaveCount 512
        foreach ($comparison in $comparisons) {
            $comparison.Actual | Should -BeExactly $comparison.Expected
        }
    }

    It 'Should reject a mask outside the 32-bit range' {
        {
            & $script:module {
                ConvertTo-WindowsAccessRightsDisplay `
                    -AccessMask 0x100000000L `
                    -RightsType ([System.Security.AccessControl.FileSystemRights])
            }
        } | Should -Throw
    }
}
