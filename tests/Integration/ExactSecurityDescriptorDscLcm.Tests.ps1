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
        WindowsAccessControlNtfsAccessRule NtfsRule {
            Path = 'C:\Data'
            Account = 'S-1-1-0'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            AppliesTo = 'ThisFolderOnly'
            Ensure = 'Present'
        }
        WindowsAccessControlRegistryKeyAccessRule RegistryRule {
            Path = 'HKLM:\Software\Contoso'
            RegistryView = 'Default'
            Account = 'S-1-1-0'
            AccessRights = 'ReadKey'
            AccessControlType = 'Allow'
            AppliesTo = 'ThisKeyOnly'
            Ensure = 'Present'
        }
        WindowsAccessControlServiceAccessRule ServiceRule {
            Name = 'BITS'
            Account = 'S-1-1-0'
            ServiceRights = 'QueryStatus'
            AccessControlType = 'Allow'
            Ensure = 'Present'
        }
        WindowsAccessControlServiceControlManagerAccessRule ScmRule {
            Account = 'S-1-1-0'
            ControlManagerRights = 'Connect'
            AccessControlType = 'Allow'
            Ensure = 'Present'
        }
        WindowsAccessControlProcessAccessRule ProcessRule {
            ProcessId = 4
            CreationTimeFileTime = 1
            Account = 'S-1-1-0'
            ProcessRights = 'QueryLimitedInformation'
            AccessControlType = 'Allow'
            Ensure = 'Present'
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
                'WindowsAccessControlNtfsAccessRule'
                'WindowsAccessControlRegistryKeyAccessRule'
                'WindowsAccessControlServiceAccessRule'
                'WindowsAccessControlServiceControlManagerAccessRule'
                'WindowsAccessControlProcessAccessRule'
            )) {
            $mof | Should -Match ([regex]::Escape($resourceName))
        }
    }

    It 'Should compile every enterprise resource into one MOF' {
        $outputPath = Join-Path $TestDrive 'EnterpriseDescriptorConfiguration'
        $configurationText = @'
Configuration WindowsAccessControlEnterpriseConfiguration {
    Import-DscResource -ModuleName @{
        ModuleName = 'WindowsAccessControl'
        RequiredVersion = '__MODULE_VERSION__'
    }
    Node localhost {
        WindowsAccessControlSmbShareSecurityDescriptor Share {
            Name = 'WacDsc$'
            Sections = 'Access'
            Sddl = 'D:(A;;FA;;;BA)'
        }
        WindowsAccessControlADObjectSecurityDescriptor AdObject {
            DistinguishedName = 'OU=WacDsc,DC=contoso,DC=com'
            Sections = 'Access'
            AllowedBaseDistinguishedName = 'OU=WacDsc,DC=contoso,DC=com'
            Server = 'dc1.contoso.com'
            Sddl = 'D:(A;;RP;;;S-1-1-0)'
        }
        WindowsAccessControlTaskFolderSecurityDescriptor TaskFolder {
            Path = '\WacDsc'
            Sections = 'Access'
            AllowedRootPath = '\WacDsc'
            Sddl = 'D:(A;;FA;;;BA)'
        }
        WindowsAccessControlScheduledTaskSecurityDescriptor ScheduledTask {
            TaskPath = '\WacDsc'
            TaskName = 'WacDscTask'
            Sections = 'Access'
            AllowedRootPath = '\WacDsc'
            Sddl = 'D:(A;;FA;;;BA)'
        }
        WindowsAccessControlCertificatePrivateKeySecurityDescriptor PrivateKey {
            ProviderName = 'Microsoft Software Key Storage Provider'
            KeyName = 'WacDscKey'
            KeyScope = 'Machine'
            Sections = 'Access'
            Sddl = 'D:(A;;FA;;;BA)'
        }
        WindowsAccessControlSmbShareAccessRule ShareRule {
            Name = 'WacDsc$'
            Account = 'S-1-1-0'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            Ensure = 'Present'
        }
        WindowsAccessControlADObjectAccessRule AdObjectRule {
            DistinguishedName = 'OU=WacDsc,DC=contoso,DC=com'
            Account = 'S-1-1-0'
            AccessRights = 'ReadProperty'
            AccessControlType = 'Allow'
            InheritanceType = 'None'
            ObjectType = ''
            InheritedObjectType = ''
            AllowedBaseDistinguishedName = 'OU=WacDsc,DC=contoso,DC=com'
            Server = 'dc1.contoso.com'
            Ensure = 'Present'
        }
        WindowsAccessControlTaskFolderAccessRule TaskFolderRule {
            Path = '\WacDsc'
            Account = 'S-1-1-0'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            AppliesTo = 'ThisFolderOnly'
            AllowedRootPath = '\WacDsc'
            Ensure = 'Present'
        }
        WindowsAccessControlScheduledTaskAccessRule ScheduledTaskRule {
            TaskPath = '\WacDsc'
            TaskName = 'WacDscTask'
            Account = 'S-1-1-0'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            AllowedRootPath = '\WacDsc'
            Ensure = 'Present'
        }
        WindowsAccessControlCertificatePrivateKeyAccessRule PrivateKeyRule {
            ProviderName = 'Microsoft Software Key Storage Provider'
            KeyName = 'WacDscKey'
            KeyScope = 'Machine'
            Account = 'S-1-1-0'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            Ensure = 'Present'
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

        WindowsAccessControlEnterpriseConfiguration `
            -OutputPath $outputPath `
            -ErrorAction Stop

        $mofPath = Join-Path $outputPath 'localhost.mof'
        Test-Path -LiteralPath $mofPath -PathType Leaf | Should -BeTrue
        $mof = Get-Content -LiteralPath $mofPath -Raw
        foreach ($resourceName in @(
                'WindowsAccessControlSmbShareSecurityDescriptor'
                'WindowsAccessControlADObjectSecurityDescriptor'
                'WindowsAccessControlTaskFolderSecurityDescriptor'
                'WindowsAccessControlScheduledTaskSecurityDescriptor'
                'WindowsAccessControlCertificatePrivateKeySecurityDescriptor'
                'WindowsAccessControlSmbShareAccessRule'
                'WindowsAccessControlADObjectAccessRule'
                'WindowsAccessControlTaskFolderAccessRule'
                'WindowsAccessControlScheduledTaskAccessRule'
                'WindowsAccessControlCertificatePrivateKeyAccessRule'
            )) {
            $mof | Should -Match ([regex]::Escape($resourceName))
        }
    }

    It 'Should advertise every packaged resource to the DSC engine' {
        $advertised = @(
            Get-DscResource -Module @{
                ModuleName      = 'WindowsAccessControl'
                RequiredVersion = $script:moduleVersion
            } -ErrorAction Stop
        ).Name

        $manifestResources = @(
            (Import-PowerShellDataFile -LiteralPath (
                Join-Path $script:machineModulePath 'WindowsAccessControl.psd1'
            )).DscResourcesToExport
        )

        $manifestResources.Count | Should -BeGreaterThan 0
        foreach ($resourceName in $manifestResources) {
            $advertised | Should -Contain $resourceName
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

    It 'Should invoke NTFS access-rule presence through the DSC engine' {
        $path = Join-Path $TestDrive 'invoke-dsc-rule-resource.txt'
        Set-Content -LiteralPath $path -Value 'test'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $path `
            -Sections Access
        $moduleSpecification = @{
            ModuleName = 'WindowsAccessControl'
            RequiredVersion = $script:moduleVersion
        }
        $ruleProperties = @{
            Path = $path
            Account = 'S-1-5-21-4242424242-4242424242-4242424242-5299'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            AppliesTo = 'ThisFolderOnly'
            Ensure = 'Present'
        }
        $ruleParameters = @{
            Name = 'WindowsAccessControlNtfsAccessRule'
            ModuleName = $moduleSpecification
            Property = $ruleProperties
            ErrorAction = 'Stop'
        }
        try {
            (Invoke-DscResource @ruleParameters -Method Test).InDesiredState |
                Should -BeFalse
            $null = Invoke-DscResource @ruleParameters -Method Set
            (Invoke-DscResource @ruleParameters -Method Test).InDesiredState |
                Should -BeTrue

            $ruleProperties.Ensure = 'Absent'
            (Invoke-DscResource @ruleParameters -Method Test).InDesiredState |
                Should -BeFalse
            $null = Invoke-DscResource @ruleParameters -Method Set
            (Invoke-DscResource @ruleParameters -Method Test).InDesiredState |
                Should -BeTrue
        } finally {
            $exactParameters = @{
                Name = 'WindowsAccessControlNtfsSecurityDescriptor'
                ModuleName = $moduleSpecification
                Method = 'Set'
                Property = @{
                    Path = $path
                    Sections = 'Access'
                    Sddl = $descriptor.Sddl
                }
                ErrorAction = 'Stop'
            }
            $null = Invoke-DscResource @exactParameters
        }
    }
}
