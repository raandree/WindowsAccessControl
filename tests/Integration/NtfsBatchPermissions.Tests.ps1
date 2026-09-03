BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'NTFS batch execution' -Tag 'Integration', 'WindowsOnly' {
    It 'Should deduplicate canonical paths and record one batch metric' {
        $first = Join-Path -Path $TestDrive -ChildPath 'first.txt'
        $second = Join-Path -Path $TestDrive -ChildPath 'second.txt'
        Set-Content -LiteralPath $first -Value 'first'
        Set-Content -LiteralPath $second -Value 'second'
        $wildcard = Join-Path -Path $TestDrive -ChildPath '*.txt'
        $before = Get-WindowsAccessControlMetric `
            -CommandName 'Get-NTFSItemOwner' `
            -ObjectFamily 'FileSystem'
        $beforeOperations = if ($before) { $before.OperationCount } else { 0 }
        $beforeTargets = if ($before) { $before.TargetCount } else { 0 }
        $beforeSuccesses = if ($before) { $before.SuccessCount } else { 0 }
        $beforeFailures = if ($before) { $before.FailureCount } else { 0 }

        $result = @(Get-NTFSItemOwner `
            -Path @($first, $wildcard) `
            -ThrottleLimit 2)
        $after = Get-WindowsAccessControlMetric `
            -CommandName 'Get-NTFSItemOwner' `
            -ObjectFamily 'FileSystem'

        $result | Should -HaveCount 2
        @($result.Path | Sort-Object -Unique) | Should -HaveCount 2
        $after.OperationCount - $beforeOperations | Should -Be 1
        $after.TargetCount - $beforeTargets | Should -Be 2
        $after.SuccessCount - $beforeSuccesses | Should -Be 2
        $after.FailureCount - $beforeFailures | Should -Be 0
    }

    It 'Should reject an invalid batch before dispatching any target' {
        $validPath = Join-Path -Path $TestDrive -ChildPath 'valid.txt'
        $missingPath = Join-Path -Path $TestDrive -ChildPath 'missing.txt'
        Set-Content -LiteralPath $validPath -Value 'valid'
        $before = Get-WindowsAccessControlMetric `
            -CommandName 'Get-NTFSItemOwner' `
            -ObjectFamily 'FileSystem'
        $beforeOperations = if ($before) { $before.OperationCount } else { 0 }

        {
            Get-NTFSItemOwner `
                -LiteralPath @($validPath, $missingPath) `
                -ThrottleLimit 2
        } | Should -Throw
        $after = Get-WindowsAccessControlMetric `
            -CommandName 'Get-NTFSItemOwner' `
            -ObjectFamily 'FileSystem'
        $afterOperations = if ($after) { $after.OperationCount } else { 0 }

        $afterOperations - $beforeOperations | Should -Be 0
    }

    It 'Should mutate multiple independent targets with bounded execution' {
        $first = Join-Path -Path $TestDrive -ChildPath 'mutate-first.txt'
        $second = Join-Path -Path $TestDrive -ChildPath 'mutate-second.txt'
        $testSid = 'S-1-5-21-4242424242-4242424242-4242424242-4998'
        Set-Content -LiteralPath $first -Value 'first'
        Set-Content -LiteralPath $second -Value 'second'
        # This assertion has lost a target three times in a whole instrumented
        # run and never in isolation, and the count told nobody why. The error
        # stream of each batch is captured so the next occurrence names it.
        $addErrors = @()
        $readErrors = @()

        Add-NTFSAccessRule `
            -LiteralPath @($first, $second) `
            -Account $testSid `
            -AccessRights Read `
            -ThrottleLimit 2 `
            -Confirm:$false `
            -ErrorVariable +addErrors
        $storedRules = @(Get-NTFSAccessRule `
            -LiteralPath @($first, $second) `
            -Account $testSid `
            -ExcludeInherited `
            -ThrottleLimit 2 `
            -ErrorVariable +readErrors)

        @($addErrors) | Should -BeNullOrEmpty
        @($readErrors) | Should -BeNullOrEmpty
        $storedRules | Should -HaveCount 2
        @($storedRules.Path | Sort-Object -Unique) | Should -HaveCount 2
    }

    It 'Should not mutate any target during a parallel WhatIf preview' {
        $first = Join-Path -Path $TestDrive -ChildPath 'whatif-first.txt'
        $second = Join-Path -Path $TestDrive -ChildPath 'whatif-second.txt'
        $testSid = 'S-1-5-21-4242424242-4242424242-4242424242-4999'
        Set-Content -LiteralPath $first -Value 'first'
        Set-Content -LiteralPath $second -Value 'second'

        Add-NTFSAccessRule `
            -LiteralPath @($first, $second) `
            -Account $testSid `
            -AccessRights Write `
            -ThrottleLimit 2 `
            -WhatIf

        Get-NTFSAccessRule `
            -LiteralPath @($first, $second) `
            -Account $testSid `
            -ExcludeInherited `
            -ThrottleLimit 2 |
            Should -BeNullOrEmpty
    }
}
