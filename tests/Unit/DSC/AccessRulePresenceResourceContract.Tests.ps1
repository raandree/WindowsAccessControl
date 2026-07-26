BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    $script:manifestData = Import-PowerShellDataFile -Path $moduleManifest.FullName
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl
}

AfterAll {
    Remove-Module -Name WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Access-rule presence DSC resource contract' -Tag 'Unit', 'WindowsOnly' {
    It 'Should expose the WindowsAccessControlDscEnsure enum' {
        ([System.Management.Automation.PSTypeName]'WindowsAccessControlDscEnsure').Type |
            Should -Not -BeNullOrEmpty
        [enum]::GetNames(
            ([System.Management.Automation.PSTypeName]'WindowsAccessControlDscEnsure').Type
        ) | Should -Be @('Absent', 'Present')
    }

    It 'Should export and discover <Name>' -ForEach @(
        @{
            Name = 'WindowsAccessControlNtfsAccessRule'
            KeyNames = @('Path', 'Account', 'AccessRights', 'AccessControlType', 'AppliesTo')
            Properties = @(
                'Path', 'Account', 'AccessRights', 'AccessControlType', 'AppliesTo',
                'Ensure', 'Reasons'
            )
        }
        @{
            Name = 'WindowsAccessControlRegistryKeyAccessRule'
            KeyNames = @(
                'Path', 'RegistryView', 'Account', 'AccessRights',
                'AccessControlType', 'AppliesTo'
            )
            Properties = @(
                'Path', 'RegistryView', 'Account', 'AccessRights',
                'AccessControlType', 'AppliesTo', 'Ensure', 'Reasons'
            )
        }
        @{
            Name = 'WindowsAccessControlServiceAccessRule'
            KeyNames = @('Name', 'Account', 'ServiceRights', 'AccessControlType')
            Properties = @(
                'Name', 'Account', 'ServiceRights', 'AccessControlType',
                'Ensure', 'Reasons'
            )
        }
        @{
            Name = 'WindowsAccessControlServiceControlManagerAccessRule'
            KeyNames = @('Account', 'ControlManagerRights', 'AccessControlType')
            Properties = @(
                'Account', 'ControlManagerRights', 'AccessControlType',
                'Ensure', 'Reasons'
            )
        }
        @{
            Name = 'WindowsAccessControlProcessAccessRule'
            KeyNames = @(
                'ProcessId', 'CreationTimeFileTime', 'Account', 'ProcessRights',
                'AccessControlType'
            )
            Properties = @(
                'ProcessId', 'CreationTimeFileTime', 'Account', 'ProcessRights',
                'AccessControlType', 'Ensure', 'Reasons'
            )
        }
    ) {
        $script:manifestData.DscResourcesToExport | Should -Contain $Name
        (Get-DscResource -Name $Name -Module WindowsAccessControl -ErrorAction Stop).Name |
            Should -Be $Name

        $resourceType = & $script:module ([scriptblock]::Create("[$Name]"))
        $resourceProperties = @($resourceType.GetProperties() | Where-Object {
            @($_.GetCustomAttributes($true) | Where-Object {
                $_ -is [System.Management.Automation.DscPropertyAttribute]
            }).Count -eq 1
        })
        @($resourceProperties.Name | Sort-Object) |
            Should -Be @($Properties | Sort-Object)
        @($resourceProperties | Where-Object {
            @($_.GetCustomAttributes($true) | Where-Object {
                $_ -is [System.Management.Automation.DscPropertyAttribute]
            })[0].Key
        }).Name | Sort-Object | Should -Be @($KeyNames | Sort-Object)
        @($resourceProperties | Where-Object Name -eq Reasons)[0].
            GetCustomAttributes($true)[0].NotConfigurable |
            Should -BeTrue

        $instance = [System.Activator]::CreateInstance($resourceType)
        $instance.Ensure.ToString() | Should -Be Present
    }
}
