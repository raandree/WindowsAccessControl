BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:testId = [guid]::NewGuid().ToString('N')
    $script:root = 'HKCU:\Software\WindowsAccessControlInheritanceTest'
    $script:grandparentPath = Join-Path $script:root $script:testId
    $script:parentPath = Join-Path $script:grandparentPath 'Parent'
    $script:childPath = Join-Path $script:parentPath 'Child'
    $script:grandparentSid = 'S-1-5-21-1111111111-2222222222-3333333333-9001'
    $script:parentSid = 'S-1-5-21-1111111111-2222222222-3333333333-9002'
    $script:explicitSid = 'S-1-5-21-1111111111-2222222222-3333333333-9003'

    $null = New-Item -Path $script:childPath -Force -ErrorAction Stop

    Add-RegistryKeyAccessRule -Path $script:grandparentPath `
        -Account $script:grandparentSid `
        -AccessRights ReadKey `
        -AppliesTo ThisKeyAndSubkeys `
        -Confirm:$false
    Add-RegistryKeyAccessRule -Path $script:parentPath `
        -Account $script:parentSid `
        -AccessRights ReadKey `
        -AppliesTo ThisKeyAndSubkeys `
        -Confirm:$false
    Add-RegistryKeyAccessRule -Path $script:childPath `
        -Account $script:explicitSid `
        -AccessRights ReadKey `
        -AppliesTo ThisKeyOnly `
        -Confirm:$false
}

AfterAll {
    Remove-Item -LiteralPath $script:grandparentPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $script:root -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $script:root).Count -eq 0) {
            Remove-Item -LiteralPath $script:root -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-RegistryKeyAccessRule inheritance source' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report the ancestor key of an inherited rule' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath `
            -Account $script:parentSid `
            -ExcludeExplicit)

        $result | Should -HaveCount 1
        $result.IsInherited | Should -BeTrue
        $result.InheritedFrom | Should -Be $script:parentPath
    }

    It 'Should report the original ancestor rather than the nearest parent' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath `
            -Account $script:grandparentSid `
            -ExcludeExplicit)

        $result | Should -HaveCount 1
        $result.InheritedFrom | Should -Be $script:grandparentPath
        $result.InheritedFrom | Should -Not -Be $script:parentPath
    }

    It 'Should leave the inheritance source empty for an explicit rule' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath `
            -Account $script:explicitSid `
            -ExcludeInherited)

        $result | Should -HaveCount 1
        $result.IsInherited | Should -BeFalse
        ($null -eq $result.InheritedFrom) | Should -BeTrue
    }

    It 'Should align every rule of an unfiltered read with its native source' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath)
        $selected = @($result | Where-Object SID -In @(
            $script:grandparentSid,
            $script:parentSid,
            $script:explicitSid
        ))

        $selected | Should -HaveCount 3
        ($selected | Where-Object SID -EQ $script:grandparentSid).InheritedFrom |
            Should -Be $script:grandparentPath
        ($selected | Where-Object SID -EQ $script:parentSid).InheritedFrom |
            Should -Be $script:parentPath
        $explicitRule = $selected | Where-Object SID -EQ $script:explicitSid
        ($null -eq $explicitRule.InheritedFrom) | Should -BeTrue
    }

    It 'Should accept RegistryKey pipeline input' {
        $result = @(Get-Item -LiteralPath $script:childPath |
            Get-RegistryKeyAccessRule -Account $script:parentSid -ExcludeExplicit)

        $result | Should -HaveCount 1
        $result.InheritedFrom | Should -Be $script:parentPath
    }

    It 'Should omit the inheritance source when a WOW64 view is selected' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath `
            -RegistryView Registry64 `
            -Account $script:parentSid `
            -ExcludeExplicit)

        $result | Should -HaveCount 1
        $result.IsInherited | Should -BeTrue
        ($null -eq $result.InheritedFrom) | Should -BeTrue
    }

    It 'Should omit the inheritance source when inherited rules are excluded' {
        $result = @(Get-RegistryKeyAccessRule -Path $script:childPath -ExcludeInherited)

        $result | Should -Not -BeNullOrEmpty
        @($result | Where-Object { $null -ne $_.InheritedFrom }) | Should -HaveCount 0
    }
}
