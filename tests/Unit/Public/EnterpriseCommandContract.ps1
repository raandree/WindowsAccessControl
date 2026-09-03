function Register-EnterpriseCommandContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$RequiredParameters,

        [Parameter(Mandatory)]
        [bool]$SupportsShouldProcess,

        [Parameter()]
        [bool]$SupportsTargetArrays = $true
    )

    $testCase = @{
        Name                  = $Name
        RequiredParameters    = @($RequiredParameters)
        SupportsShouldProcess = $SupportsShouldProcess
        SupportsTargetArrays  = $SupportsTargetArrays
    }

    Describe '<Name> public contract' -ForEach $testCase -Tag 'Unit', 'WindowsOnly' {
        BeforeAll {
            $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
                Sort-Object -Property { [version]$_.Directory.Name } -Descending |
                Select-Object -First 1
            Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
        }

        It 'Should export the expected parameter contract' {
            $command = Get-Command -Name $Name -Module 'WindowsAccessControl' -ErrorAction Stop

            foreach ($parameterName in $RequiredParameters) {
                $command.Parameters.ContainsKey($parameterName) |
                    Should -BeTrue -Because "$Name requires the $parameterName parameter"
            }
            $command.Parameters.ContainsKey('ThrottleLimit') |
                Should -Be $SupportsTargetArrays
            $command.Parameters.ContainsKey('WhatIf') |
                Should -Be $SupportsShouldProcess
        }
    }
}
