# Registry target resolution table and rights facts (FR-32).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl

    function script:Resolve-Target {
        param(
            [Parameter(Mandatory)]
            [object]$Path,

            [Parameter()]
            [string]$RegistryView = 'Default'
        )

        & $script:module {
            param($Path, $RegistryView)

            Resolve-RegistryKeyTarget -Path $Path -RegistryView $RegistryView
        } $Path $RegistryView
    }
}

Describe 'Resolve-RegistryKeyTarget accepted forms' -Tag 'Unit', 'WindowsOnly' {
    It 'Should resolve <Path> to <ExpectedPath>' -ForEach @(
        @{ Path = 'HKEY_LOCAL_MACHINE\SOFTWARE'; ExpectedPath = 'HKLM:\SOFTWARE'; ExpectedNative = 'MACHINE\SOFTWARE' }
        @{ Path = 'HKLM:\SOFTWARE'; ExpectedPath = 'HKLM:\SOFTWARE'; ExpectedNative = 'MACHINE\SOFTWARE' }
        @{ Path = 'MACHINE\SOFTWARE'; ExpectedPath = 'HKLM:\SOFTWARE'; ExpectedNative = 'MACHINE\SOFTWARE' }
        @{ Path = 'HKEY_CURRENT_USER\Software'; ExpectedPath = 'HKCU:\Software'; ExpectedNative = 'CURRENT_USER\Software' }
        @{ Path = 'HKCU:\Software'; ExpectedPath = 'HKCU:\Software'; ExpectedNative = 'CURRENT_USER\Software' }
        @{ Path = 'CURRENT_USER\Software'; ExpectedPath = 'HKCU:\Software'; ExpectedNative = 'CURRENT_USER\Software' }
        @{ Path = 'HKEY_CLASSES_ROOT\.txt'; ExpectedPath = 'HKCR:\.txt'; ExpectedNative = 'CLASSES_ROOT\.txt' }
        @{ Path = 'HKCR:\.txt'; ExpectedPath = 'HKCR:\.txt'; ExpectedNative = 'CLASSES_ROOT\.txt' }
        @{ Path = 'CLASSES_ROOT\.txt'; ExpectedPath = 'HKCR:\.txt'; ExpectedNative = 'CLASSES_ROOT\.txt' }
        @{ Path = 'HKEY_USERS\.DEFAULT'; ExpectedPath = 'HKU:\.DEFAULT'; ExpectedNative = 'USERS\.DEFAULT' }
        @{ Path = 'HKU:\.DEFAULT'; ExpectedPath = 'HKU:\.DEFAULT'; ExpectedNative = 'USERS\.DEFAULT' }
        @{ Path = 'USERS\.DEFAULT'; ExpectedPath = 'HKU:\.DEFAULT'; ExpectedNative = 'USERS\.DEFAULT' }
        @{ Path = 'HKLM'; ExpectedPath = 'HKLM:'; ExpectedNative = 'MACHINE' }
        @{
            Path           = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE'
            ExpectedPath   = 'HKLM:\SOFTWARE'
            ExpectedNative = 'MACHINE\SOFTWARE'
        }
        @{ Path = 'HKLM:/SOFTWARE'; ExpectedPath = 'HKLM:\SOFTWARE'; ExpectedNative = 'MACHINE\SOFTWARE' }
    ) {
        $target = Resolve-Target -Path $Path

        $target.Path | Should -Be $ExpectedPath
        $target.NativePath | Should -Be $ExpectedNative
        $target.ObjectType | Should -Be 'RegistryKey'
    }

    It 'Should expand a current-config target to the hardware profile subtree' -ForEach @(
        @{ Path = 'HKEY_CURRENT_CONFIG' }
        @{ Path = 'HKCC:' }
    ) {
        $target = Resolve-Target -Path $Path

        $target.NativePath |
            Should -Be 'MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles\Current'
        $target.Path |
            Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Hardware Profiles\Current'
    }

    It 'Should carry the requested view into the canonical target' -ForEach @(
        @{ RegistryView = 'Default' }
        @{ RegistryView = 'Registry32' }
        @{ RegistryView = 'Registry64' }
    ) {
        $target = Resolve-Target -Path 'HKLM:\SOFTWARE' -RegistryView $RegistryView

        $target.RegistryView | Should -Be $RegistryView
        $target.CanonicalTarget | Should -Be ('RegistryKey:{0}:MACHINE\SOFTWARE' -f $RegistryView)
    }
}

Describe 'Resolve-RegistryKeyTarget rejected forms' -Tag 'Unit', 'WindowsOnly' {
    It 'Should reject <Label>' -ForEach @(
        @{ Label = 'a forward-slash hive form'; Path = 'HKLM/SOFTWARE' }
        @{ Label = 'an unknown hive'; Path = 'HKEY_DYN_DATA\Config' }
        @{ Label = 'a native remote path'; Path = '\\server\HKLM\SOFTWARE' }
        @{ Label = 'a provider-qualified remote path'; Path = 'Microsoft.PowerShell.Core\Registry::\\server\HKLM' }
        @{ Label = 'an empty path'; Path = '   ' }
    ) {
        { Resolve-Target -Path $Path } | Should -Throw
    }
}

Describe 'Registry rights facts' -Tag 'Unit', 'WindowsOnly' {
    It 'Should pin RegistryRights.FullControl to KEY_ALL_ACCESS without SYNCHRONIZE' {
        # FullControl is 983103, which is KEY_ALL_ACCESS (0xF003F). Unlike the
        # file system FullControl it carries no SYNCHRONIZE bit, because a
        # registry key cannot be waited on.
        [int][System.Security.AccessControl.RegistryRights]::FullControl | Should -Be 983103
        [int][System.Security.AccessControl.RegistryRights]::FullControl | Should -Be 0xF003F
        ([int][System.Security.AccessControl.RegistryRights]::FullControl -band 0x00100000) |
            Should -Be 0
    }

    It 'Should pin ReadKey and ExecuteKey to the same value' {
        [int][System.Security.AccessControl.RegistryRights]::ReadKey | Should -Be 131097
        [int][System.Security.AccessControl.RegistryRights]::ExecuteKey | Should -Be 131097
    }

    It 'Should render the shared ReadKey and ExecuteKey value without a name flip' {
        $display = & $script:module {
            ConvertTo-WindowsAccessRightsDisplay `
                -AccessMask 131097 `
                -RightsType ([System.Security.AccessControl.RegistryRights])
        }

        # One value, one name. The round trip must not invent the other name.
        $display | Should -Be 'ReadKey'
    }

    It 'Should never let a registry rights value carry SYNCHRONIZE' {
        $synchronize = 0x00100000
        foreach ($value in [System.Enum]::GetValues([System.Security.AccessControl.RegistryRights])) {
            ([int]$value -band $synchronize) | Should -Be 0
        }
    }
}

Describe 'Registry redirection literal' -Tag 'Unit', 'WindowsOnly' {
    It 'Should never address the reserved redirection node by name' {
        # The node is reserved; a view flag is the only supported way to address
        # the redirected tree. The literal is assembled here so this assertion
        # does not become its own violation.
        $reservedNode = 'Wow' + '6432Node'
        $repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
        $offenders = @(
            Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'source') -Recurse -File -Filter '*.ps1' |
                Select-String -SimpleMatch $reservedNode |
                ForEach-Object { $_.Path }
        )

        $offenders | Should -BeNullOrEmpty
    }
}
