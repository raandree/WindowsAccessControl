BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should filter explicit access rules by SID' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'filter.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Read

        $result = Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited

        $result | Should -HaveCount 1
        $result.SID | Should -Be $script:currentSid
        $result.IsInherited | Should -BeFalse
        ($null -eq $result.InheritedFrom) | Should -BeTrue
    }

    It 'Should report the ancestor of an inherited access rule' {
        $parentPath = Join-Path -Path $TestDrive -ChildPath 'parent'
        $childPath = Join-Path -Path $parentPath -ChildPath 'child'
        $inheritedSid = 'S-1-5-21-1111111111-2222222222-3333333333-5555'
        $null = New-Item -Path $childPath -ItemType Directory -Force
        Add-NTFSAccessRule `
            -LiteralPath $parentPath `
            -Account $inheritedSid `
            -AccessRights Read `
            -AppliesTo ThisFolderSubfoldersAndFiles

        $result = Get-NTFSAccessRule `
            -LiteralPath $childPath `
            -Account $inheritedSid `
            -ExcludeExplicit

        $result | Should -HaveCount 1
        $result.IsInherited | Should -BeTrue
        $result.InheritedFrom | Should -Be $parentPath
    }

    It 'Should report the ancestor of an access rule inherited by a file' {
        $parentPath = Join-Path -Path $TestDrive -ChildPath 'file-parent'
        $childPath = Join-Path -Path $parentPath -ChildPath 'child.txt'
        $inheritedSid = 'S-1-5-21-1111111111-2222222222-3333333333-7777'
        $null = New-Item -Path $parentPath -ItemType Directory
        Set-Content -LiteralPath $childPath -Value 'test'
        Add-NTFSAccessRule `
            -LiteralPath $parentPath `
            -Account $inheritedSid `
            -AccessRights Read `
            -AppliesTo ThisFolderSubfoldersAndFiles

        $result = Get-NTFSAccessRule `
            -LiteralPath $childPath `
            -Account $inheritedSid `
            -ExcludeExplicit

        $result | Should -HaveCount 1
        $result.IsInherited | Should -BeTrue
        $result.InheritedFrom | Should -Be $parentPath
    }

    It 'Should report the original ancestor when the parent has the same inherited rule' {
        $grandparentPath = Join-Path -Path $TestDrive -ChildPath 'grandparent'
        $parentPath = Join-Path -Path $grandparentPath -ChildPath 'parent'
        $childPath = Join-Path -Path $parentPath -ChildPath 'child'
        $inheritedSid = 'S-1-5-21-1111111111-2222222222-3333333333-6666'
        $null = New-Item -Path $childPath -ItemType Directory -Force
        Add-NTFSAccessRule `
            -LiteralPath $grandparentPath `
            -Account $inheritedSid `
            -AccessRights Read `
            -AppliesTo ThisFolderSubfoldersAndFiles

        $result = @(Get-NTFSAccessRule `
            -LiteralPath $childPath `
            -Account $inheritedSid `
            -ExcludeExplicit)

        $result | Should -HaveCount 1
        $result.InheritedFrom | Should -Be $grandparentPath
        $result.InheritedFrom | Should -Not -Be $parentPath
    }

    It 'Should align explicit and inherited rules with their native sources' {
        $grandparentPath = Join-Path -Path $TestDrive -ChildPath 'mixed-grandparent'
        $parentPath = Join-Path -Path $grandparentPath -ChildPath 'parent'
        $childPath = Join-Path -Path $parentPath -ChildPath 'child'
        $grandparentSid = 'S-1-5-21-1111111111-2222222222-3333333333-8001'
        $parentSid = 'S-1-5-21-1111111111-2222222222-3333333333-8002'
        $explicitSid = 'S-1-5-21-1111111111-2222222222-3333333333-8003'
        $null = New-Item -Path $childPath -ItemType Directory -Force
        Add-NTFSAccessRule `
            -LiteralPath $grandparentPath `
            -Account $grandparentSid `
            -AccessRights Read `
            -AppliesTo ThisFolderSubfoldersAndFiles
        Add-NTFSAccessRule `
            -LiteralPath $parentPath `
            -Account $parentSid `
            -AccessRights Write `
            -AppliesTo ThisFolderSubfoldersAndFiles
        Add-NTFSAccessRule `
            -LiteralPath $childPath `
            -Account $explicitSid `
            -AccessRights Modify

        $result = @(Get-NTFSAccessRule -LiteralPath $childPath)
        $selectedRules = @($result | Where-Object SID -In @(
            $grandparentSid,
            $parentSid,
            $explicitSid
        ))

        $selectedRules | Should -HaveCount 3
        ($selectedRules | Where-Object SID -EQ $grandparentSid).InheritedFrom |
            Should -Be $grandparentPath
        ($selectedRules | Where-Object SID -EQ $parentSid).InheritedFrom |
            Should -Be $parentPath
        $explicitRule = $selectedRules | Where-Object SID -EQ $explicitSid
        ($null -eq $explicitRule.InheritedFrom) | Should -BeTrue
    }
}
