BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    $script:manifestData = Import-PowerShellDataFile -Path $moduleManifest.FullName
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Exact security descriptor DSC resource contract' -Tag 'Unit', 'WindowsOnly' {
    It 'Should export and discover <Name>' -ForEach @(
        @{
            Name       = 'WindowsAccessControlNtfsSecurityDescriptor'
            KeyNames   = @('Path', 'Sections')
            Properties = @('Path', 'Sections', 'Sddl', 'Reasons')
        }
        @{
            Name       = 'WindowsAccessControlRegistryKeySecurityDescriptor'
            KeyNames   = @('Path', 'RegistryView', 'Sections')
            Properties = @('Path', 'RegistryView', 'Sections', 'Sddl', 'Reasons')
        }
        @{
            Name       = 'WindowsAccessControlServiceSecurityDescriptor'
            KeyNames   = @('Name', 'Sections')
            Properties = @('Name', 'Sections', 'Sddl', 'Reasons')
        }
        @{
            Name       = 'WindowsAccessControlServiceControlManagerSecurityDescriptor'
            KeyNames   = @('Sections')
            Properties = @('Sections', 'Sddl', 'Reasons')
        }
        @{
            Name       = 'WindowsAccessControlProcessSecurityDescriptor'
            KeyNames   = @('ProcessId', 'CreationTimeFileTime', 'Sections')
            Properties = @(
                'ProcessId'
                'CreationTimeFileTime'
                'Sections'
                'Sddl'
                'Reasons'
            )
        }
    ) {
        $script:manifestData.DscResourcesToExport | Should -Contain $Name

        $resource = Get-DscResource `
            -Name $Name `
            -Module WindowsAccessControl `
            -ErrorAction Stop
        $resource.Name | Should -Be $Name
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
        }).Name |
            Sort-Object |
            Should -Be @($KeyNames | Sort-Object)
        @($resourceProperties | Where-Object Name -eq 'Sddl')[0].
            GetCustomAttributes($true)[0].Mandatory |
            Should -BeTrue
        @($resourceProperties | Where-Object Name -eq 'Reasons')[0].
            GetCustomAttributes($true)[0].NotConfigurable |
            Should -BeTrue
    }
}
