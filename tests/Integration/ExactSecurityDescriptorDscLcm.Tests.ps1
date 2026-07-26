if ($PSVersionTable.PSEdition -eq 'Core') {
    return
}

BeforeAll {
    $script:moduleRoot = (Resolve-Path "$PSScriptRoot\..\..\output\module").Path
    $script:originalPSModulePath = $env:PSModulePath
    $moduleManifest = Get-ChildItem -Path "$script:moduleRoot\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    $script:moduleVersion = $moduleManifest.Directory.Name
    $script:machineModuleParent = Join-Path `
        $env:ProgramFiles `
        'WindowsPowerShell\Modules\WindowsAccessControl'
    $script:machineModulePath = Join-Path `
        $script:machineModuleParent `
        $moduleManifest.Directory.Name
    if (Test-Path -LiteralPath $script:machineModulePath) {
        throw "The DSC acceptance test will not overwrite '$script:machineModulePath'."
    }
    $null = New-Item `
        -ItemType Directory `
        -Path $script:machineModuleParent `
        -Force
    Copy-Item `
        -LiteralPath $moduleManifest.Directory.FullName `
        -Destination $script:machineModulePath `
        -Recurse `
        -Force
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $normalizedModuleRoot = $script:moduleRoot.TrimEnd('\')
    $env:PSModulePath = @($env:PSModulePath -split ';' | Where-Object {
        $_.TrimEnd('\') -ne $normalizedModuleRoot
    }) -join ';'
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
    if ($script:machineModulePath) {
        Remove-Item `
            -LiteralPath $script:machineModulePath `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
    if ($script:machineModuleParent -and
        (Test-Path -LiteralPath $script:machineModuleParent) -and
        @(Get-ChildItem -LiteralPath $script:machineModuleParent).Count -eq 0) {
        Remove-Item `
            -LiteralPath $script:machineModuleParent `
            -Force `
            -ErrorAction SilentlyContinue
    }
    if ($script:originalPSModulePath) {
        $env:PSModulePath = $script:originalPSModulePath
    }
}

Describe 'Exact security descriptor DSC LCM contract' -Tag 'Integration', 'WindowsOnly' {
    It 'Should compile all exact descriptor resources into one MOF' {
        $outputPath = Join-Path $TestDrive 'ExactDescriptorConfiguration'
        $configurationText = @'
Configuration WindowsAccessControlExactDescriptorConfiguration {
    Import-DscResource -ModuleName @{
        ModuleName = 'WindowsAccessControl'
        RequiredVersion = '__MODULE_VERSION__'
    }
    Node localhost {
        WindowsAccessControlNtfsSecurityDescriptor Ntfs {
            Path = 'C:\Data'
            Sections = 'All'
            Sddl = 'O:SYG:SYD:P(A;;FA;;;SY)S:NO_ACCESS_CONTROL'
        }
        WindowsAccessControlRegistryKeySecurityDescriptor RegistryKey {
            Path = 'HKLM:\Software\Contoso'
            RegistryView = 'Default'
            Sections = 'Access'
            Sddl = 'D:(A;;KA;;;SY)'
        }
        WindowsAccessControlServiceSecurityDescriptor Service {
            Name = 'BITS'
            Sections = 'Access'
            Sddl = 'D:(A;;CC;;;SY)'
        }
        WindowsAccessControlServiceControlManagerSecurityDescriptor Scm {
            Sections = 'Access'
            Sddl = 'D:(A;;KA;;;BA)'
        }
        WindowsAccessControlProcessSecurityDescriptor Process {
            ProcessId = 4
            CreationTimeFileTime = 1
            Sections = 'Access'
            Sddl = 'D:(A;;0x001FFFFF;;;SY)'
        }
    }
}
'@
        $configurationDefinition = [scriptblock]::Create(
            $configurationText.Replace(
                '__MODULE_VERSION__',
                $script:moduleVersion
            )
        )
        . $configurationDefinition

        WindowsAccessControlExactDescriptorConfiguration `
            -OutputPath $outputPath `
            -ErrorAction Stop

        $mofPath = Join-Path $outputPath 'localhost.mof'
        Test-Path -LiteralPath $mofPath -PathType Leaf | Should -BeTrue
        $mof = Get-Content -LiteralPath $mofPath -Raw
        foreach ($resourceName in @(
                'WindowsAccessControlNtfsSecurityDescriptor'
                'WindowsAccessControlRegistryKeySecurityDescriptor'
                'WindowsAccessControlServiceSecurityDescriptor'
                'WindowsAccessControlServiceControlManagerSecurityDescriptor'
                'WindowsAccessControlProcessSecurityDescriptor'
            )) {
            $mof | Should -Match ([regex]::Escape($resourceName))
        }
    }

    It 'Should invoke an exact NTFS resource through the DSC engine' {
        $path = Join-Path $TestDrive 'invoke-dsc-resource.txt'
        Set-Content -LiteralPath $path -Value 'test'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $path `
            -Sections All
        $invokeParameters = @{
            Name       = 'WindowsAccessControlNtfsSecurityDescriptor'
            ModuleName = @{
                ModuleName = 'WindowsAccessControl'
                RequiredVersion = $script:moduleVersion
            }
            Property   = @{
                Path     = $path
                Sections = 'All'
                Sddl     = $descriptor.Sddl
            }
            ErrorAction = 'Stop'
        }

        $testResult = Invoke-DscResource @invokeParameters -Method Test
        $getResult = Invoke-DscResource @invokeParameters -Method Get

        $testResult.InDesiredState | Should -BeTrue
        $getResult.Sddl | Should -BeExactly $descriptor.Sddl
    }
}
