if ($PSVersionTable.PSEdition -eq 'Desktop') {
    return
}

BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl
    & $script:module {
        if (-not (Get-Command Get-WindowsAccessControlDscAccessRule -ErrorAction SilentlyContinue)) {
            function script:Get-WindowsAccessControlDscAccessRule {
                throw 'The test must mock this adapter.'
            }
        }
        if (-not (Get-Command Set-WindowsAccessControlDscAccessRule -ErrorAction SilentlyContinue)) {
            function script:Set-WindowsAccessControlDscAccessRule {
                throw 'The test must mock this adapter.'
            }
        }
    }

    function New-AccessRulePresenceResourceInstance {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This fixture only constructs an in-memory DSC resource.'
        )]
        param([string]$ClassName, [hashtable]$Properties)

        $resourceType = & $script:module ([scriptblock]::Create("[$ClassName]"))
        $instance = [System.Activator]::CreateInstance($resourceType)
        foreach ($propertyName in $Properties.Keys) {
            $instance.$propertyName = $Properties[$propertyName]
        }
        $instance
    }
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Access-rule presence DSC resource behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:rulePresent = $false
        Mock -ModuleName WindowsAccessControl `
            -CommandName Get-WindowsAccessControlDscAccessRule `
            -MockWith { $script:rulePresent }
        Mock -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsAccessControlDscAccessRule
    }

    It 'Should report an Ensure mismatch for <ClassName>' -ForEach @(
        @{
            ClassName = 'WindowsAccessControlNtfsAccessRule'; Family = 'FileSystem'
            Properties = @{
                Path = 'C:\Data'; Account = 'S-1-1-0'; AccessRights = 'Read'
                AccessControlType = 'Allow'; AppliesTo = 'ThisFolderOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlRegistryKeyAccessRule'; Family = 'RegistryKey'
            Properties = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Default'
                Account = 'S-1-1-0'; AccessRights = 'ReadKey'
                AccessControlType = 'Allow'; AppliesTo = 'ThisKeyOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceAccessRule'; Family = 'Service'
            Properties = @{
                Name = 'BITS'; Account = 'S-1-1-0'; ServiceRights = 'QueryStatus'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceControlManagerAccessRule'
            Family = 'ServiceControlManager'
            Properties = @{
                Account = 'S-1-1-0'; ControlManagerRights = 'Connect'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlProcessAccessRule'; Family = 'Process'
            Properties = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Account = 'S-1-1-0'; ProcessRights = 'QueryLimitedInformation'
                AccessControlType = 'Allow'
            }
        }
    ) {
        $instance = New-AccessRulePresenceResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties

        $currentState = $instance.Get()

        $currentState.Ensure.ToString() | Should -Be Absent
        $currentState.Reasons | Should -HaveCount 1
        $currentState.Reasons[0].Code |
            Should -Be "$ClassName`:$ClassName`:Ensure"
        $expectedFamily = $Family
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Get-WindowsAccessControlDscAccessRule `
            -Exactly `
            -Times 1 `
            -ParameterFilter { $ObjectFamily -eq $expectedFamily }
    }

    It 'Should report exact rule presence for <ClassName>' -ForEach @(
        @{
            ClassName = 'WindowsAccessControlNtfsAccessRule'
            Properties = @{
                Path = 'C:\Data'; Account = 'S-1-1-0'; AccessRights = 'Read'
                AccessControlType = 'Allow'; AppliesTo = 'ThisFolderOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlRegistryKeyAccessRule'
            Properties = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Default'
                Account = 'S-1-1-0'; AccessRights = 'ReadKey'
                AccessControlType = 'Allow'; AppliesTo = 'ThisKeyOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceAccessRule'
            Properties = @{
                Name = 'BITS'; Account = 'S-1-1-0'; ServiceRights = 'QueryStatus'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceControlManagerAccessRule'
            Properties = @{
                Account = 'S-1-1-0'; ControlManagerRights = 'Connect'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlProcessAccessRule'
            Properties = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Account = 'S-1-1-0'; ProcessRights = 'QueryLimitedInformation'
                AccessControlType = 'Allow'
            }
        }
    ) {
        $script:rulePresent = $true
        $instance = New-AccessRulePresenceResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties

        $instance.Test() | Should -BeTrue
    }

    It 'Should route requested rule state for <ClassName>' -ForEach @(
        @{
            ClassName = 'WindowsAccessControlNtfsAccessRule'
            Properties = @{
                Path = 'C:\Data'; Account = 'S-1-1-0'; AccessRights = 'Read'
                AccessControlType = 'Allow'; AppliesTo = 'ThisFolderOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlRegistryKeyAccessRule'
            Properties = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Default'
                Account = 'S-1-1-0'; AccessRights = 'ReadKey'
                AccessControlType = 'Allow'; AppliesTo = 'ThisKeyOnly'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceAccessRule'
            Properties = @{
                Name = 'BITS'; Account = 'S-1-1-0'; ServiceRights = 'QueryStatus'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceControlManagerAccessRule'
            Properties = @{
                Account = 'S-1-1-0'; ControlManagerRights = 'Connect'
                AccessControlType = 'Allow'
            }
        }
        @{
            ClassName = 'WindowsAccessControlProcessAccessRule'
            Properties = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Account = 'S-1-1-0'; ProcessRights = 'QueryLimitedInformation'
                AccessControlType = 'Allow'
            }
        }
    ) {
        $instance = New-AccessRulePresenceResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties
        $instance.Ensure = 'Absent'

        { $instance.Set() } | Should -Not -Throw
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsAccessControlDscAccessRule `
            -Exactly `
            -Times 1 `
            -ParameterFilter { $Ensure -eq 'Absent' }
    }
}
