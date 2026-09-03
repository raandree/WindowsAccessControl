BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
}

Describe 'Get-WindowsAccessControlMetric' -Tag 'Unit', 'WindowsOnly' {
    It 'Should aggregate redacted batch metrics by command and object family' {
        $worker = & $script:module {
            {
                param($InputValue)
                if ($InputValue -eq 2) {
                    throw 'Expected metric failure.'
                }
                $InputValue
            }
        }

        $null = & $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(1, 2, 3) `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 `
                -CommandName 'Test-MetricBatch' `
                -ObjectFamily 'RegistryKey' `
                -ErrorAction SilentlyContinue
        } $worker
        $null = & $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(4, 5) `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 `
                -CommandName 'Test-MetricBatch' `
                -ObjectFamily 'RegistryKey'
        } $worker

        $metric = Get-WindowsAccessControlMetric `
            -CommandName 'Test-MetricBatch' `
            -ObjectFamily 'RegistryKey'

        $metric.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.Metric'
        $metric.OperationCount | Should -Be 2
        $metric.TargetCount | Should -Be 5
        $metric.SuccessCount | Should -Be 4
        $metric.FailureCount | Should -Be 1
        $metric.ElapsedMilliseconds | Should -BeGreaterThan 0
        $metric.PSObject.Properties.Name | Should -Not -Contain 'Sddl'
    }
}
