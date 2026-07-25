BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:newManifestPath = Join-Path $script:repositoryRoot 'source\WindowsAccessControl.psd1'
    $script:oldManifestPath = Join-Path $script:repositoryRoot 'source\NTFSPermission.psd1'
    $script:expectedGuid = [guid]'9979f8e0-a9d0-4bf0-a84e-a2f3084c7e0c'
}

Describe 'WindowsAccessControl package rename' -Tag 'QA' {
    It 'Should use only the new package-level source files' {
        Test-Path -LiteralPath $script:newManifestPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $script:oldManifestPath | Should -BeFalse
        Test-Path -LiteralPath (
            Join-Path $script:repositoryRoot 'source\WindowsAccessControl.Format.ps1xml'
        ) -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath (
            Join-Path $script:repositoryRoot 'source\en-US\about_WindowsAccessControl.help.txt'
        ) -PathType Leaf | Should -BeTrue
    }

    It 'Should preserve module identity and point at renamed package files' {
        $manifest = Test-ModuleManifest -Path $script:newManifestPath -ErrorAction Stop

        $manifest.Guid | Should -Be $script:expectedGuid
        $manifest.RootModule | Should -Be 'WindowsAccessControl.psm1'
        $formatFileNames = $manifest.ExportedFormatFiles | Split-Path -Leaf
        $formatFileNames | Should -Contain 'WindowsAccessControl.Format.ps1xml'
    }

    It 'Should export renamed cross-domain commands only' {
        $manifestData = Import-PowerShellDataFile -Path $script:newManifestPath
        $expectedCommands = @(
            'Resolve-WindowsIdentity'
            'Get-WindowsPrivilege'
            'Test-WindowsPrivilege'
            'Enable-WindowsPrivilege'
            'Disable-WindowsPrivilege'
        )
        $removedCommands = @(
            'Resolve-NTFSIdentity'
            'Get-NTFSPrivilege'
            'Test-NTFSPrivilege'
            'Enable-NTFSPrivilege'
            'Disable-NTFSPrivilege'
        )

        foreach ($command in $expectedCommands) {
            $manifestData.FunctionsToExport | Should -Contain $command
        }
        foreach ($command in $removedCommands) {
            $manifestData.FunctionsToExport | Should -Not -Contain $command
        }
    }

    It 'Should use the WindowsAccessControl output type prefix throughout source' {
        $legacyTypeReferences = Get-ChildItem -Path (Join-Path $script:repositoryRoot 'source') -Recurse -File |
            Select-String -SimpleMatch 'NTFSPermission.'

        $legacyTypeReferences | Should -BeNullOrEmpty
    }
}
