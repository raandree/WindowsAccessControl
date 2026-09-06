BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    function Get-RightsCompletion {
        param(
            [Parameter(Mandatory)]
            [string]$InputScript
        )

        @((TabExpansion2 -inputScript $InputScript -cursorColumn $InputScript.Length).CompletionMatches)
    }
}

Describe 'Windows access rights completion' -Tag 'Unit', 'WindowsOnly' {
    Context '<CommandName> -<ParameterName>' -ForEach @(
        @{ CommandName = 'Add-NTFSAccessRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Add-NTFSAuditRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'New-NTFSAccessRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'New-NTFSAuditRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Remove-NTFSAccessRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Remove-NTFSAuditRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Set-NTFSAccessRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Set-NTFSAuditRule'; ParameterName = 'AccessRights'; Prefix = 'Mod'; Expected = 'Modify' }
        @{ CommandName = 'Add-ADObjectAccessRule'; ParameterName = 'AccessRights'; Prefix = 'ReadP'; Expected = 'ReadProperty' }
        @{ CommandName = 'Remove-ADObjectAccessRule'; ParameterName = 'AccessRights'; Prefix = 'ReadP'; Expected = 'ReadProperty' }
        @{ CommandName = 'Set-ADObjectAccessRule'; ParameterName = 'AccessRights'; Prefix = 'ReadP'; Expected = 'ReadProperty' }
    ) {
        It 'offers matching enumeration names' {
            $completion = Get-RightsCompletion -InputScript "$CommandName -$ParameterName $Prefix"

            $completion.CompletionText | Should -Contain $Expected
            $completion.ResultType | Should -Contain (
                [System.Management.Automation.CompletionResultType]::ParameterValue
            )
        }
    }

    It 'adds completion metadata to every transformed public parameter' {
        $transformedParameters = foreach ($command in Get-Command -Module WindowsAccessControl) {
            foreach ($parameter in $command.Parameters.Values) {
                if ($parameter.Attributes.TypeId.Name -contains 'WindowsAccessRightsTransformAttribute') {
                    $parameter
                }
            }
        }

        $transformedParameters | Should -Not -BeNullOrEmpty
        foreach ($parameter in $transformedParameters) {
            $parameter.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ArgumentCompleterAttribute] } |
                Should -Not -BeNullOrEmpty
        }
    }
}
