if ($PSVersionTable.PSEdition -eq 'Desktop') {
    return
}

BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
    & $script:module {
        if (-not (Get-Command -Name Get-WindowsAccessControlDscSecurityDescriptor `
                -ErrorAction SilentlyContinue)) {
            function script:Get-WindowsAccessControlDscSecurityDescriptor {
                throw 'The test must mock this adapter.'
            }
        }
        if (-not (Get-Command -Name Set-WindowsAccessControlDscSecurityDescriptor `
                -ErrorAction SilentlyContinue)) {
            function script:Set-WindowsAccessControlDscSecurityDescriptor {
                throw 'The test must mock this adapter.'
            }
        }
    }

    function New-ExactDescriptorResourceInstance {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This Pester fixture only constructs an in-memory resource instance.'
        )]
        param(
            [Parameter(Mandatory)]
            [string]$ClassName,

            [Parameter(Mandatory)]
            [hashtable]$Properties
        )

        $resourceType = & $script:module ([scriptblock]::Create("[$ClassName]"))
        $instance = [System.Activator]::CreateInstance($resourceType)
        foreach ($propertyName in $Properties.Keys) {
            $instance.$propertyName = $Properties[$propertyName]
        }
        $instance
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Exact security descriptor DSC resource behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:currentSddl = 'D:(A;;0x00000002;;;WD)'
        Mock -ModuleName WindowsAccessControl `
            -CommandName Get-WindowsAccessControlDscSecurityDescriptor `
            -MockWith {
                [pscustomobject]@{ Sddl = $script:currentSddl }
            }
        Mock -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsAccessControlDscSecurityDescriptor `
            -MockWith {}
    }

    It 'Should report an SDDL mismatch for <ClassName>' -ForEach @(
        @{
            ClassName    = 'WindowsAccessControlNtfsSecurityDescriptor'
            ObjectFamily = 'FileSystem'
            Target       = 'C:\Data'
            Properties   = @{
                Path = 'C:\Data'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName    = 'WindowsAccessControlRegistryKeySecurityDescriptor'
            ObjectFamily = 'RegistryKey'
            Target       = 'HKLM:\Software\Contoso'
            Properties   = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Registry64'
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName    = 'WindowsAccessControlServiceSecurityDescriptor'
            ObjectFamily = 'Service'
            Target       = 'BITS'
            Properties   = @{
                Name = 'BITS'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName    = 'WindowsAccessControlServiceControlManagerSecurityDescriptor'
            ObjectFamily = 'ServiceControlManager'
            Target       = $null
            Properties   = @{
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName    = 'WindowsAccessControlProcessSecurityDescriptor'
            ObjectFamily = 'Process'
            Target       = $null
            Properties   = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
    ) {
        $instance = New-ExactDescriptorResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties

        $currentState = $instance.Get()

        $currentState.Sddl | Should -BeExactly $script:currentSddl
        $currentState.Reasons | Should -HaveCount 1
        $currentState.Reasons[0].Code |
            Should -Be "$ClassName`:$ClassName`:Sddl"
        $expectedObjectFamily = $ObjectFamily
        $expectedTarget = $Target
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Get-WindowsAccessControlDscSecurityDescriptor `
            -Exactly `
            -Times 1 `
            -ParameterFilter {
                $ObjectFamily -eq $expectedObjectFamily -and
                    $Target -eq $expectedTarget
            }
    }

    It 'Should report canonical equality for <ClassName>' -ForEach @(
        @{
            ClassName = 'WindowsAccessControlNtfsSecurityDescriptor'
            Properties = @{
                Path = 'C:\Data'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlRegistryKeySecurityDescriptor'
            Properties = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Default'
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceSecurityDescriptor'
            Properties = @{
                Name = 'BITS'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceControlManagerSecurityDescriptor'
            Properties = @{
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlProcessSecurityDescriptor'
            Properties = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
    ) {
        $script:currentSddl = 'D:(A;;0x00000001;;;WD)'
        $instance = New-ExactDescriptorResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties

        $instance.Test() | Should -BeTrue
    }

    It 'Should route Set for <ClassName>' -ForEach @(
        @{
            ClassName = 'WindowsAccessControlNtfsSecurityDescriptor'
            Properties = @{
                Path = 'C:\Data'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlRegistryKeySecurityDescriptor'
            Properties = @{
                Path = 'HKLM:\Software\Contoso'; RegistryView = 'Registry32'
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceSecurityDescriptor'
            Properties = @{
                Name = 'BITS'; Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlServiceControlManagerSecurityDescriptor'
            Properties = @{
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
        @{
            ClassName = 'WindowsAccessControlProcessSecurityDescriptor'
            Properties = @{
                ProcessId = 42; CreationTimeFileTime = 123456789
                Sections = 'Access'; Sddl = 'D:(A;;0x00000001;;;WD)'
            }
        }
    ) {
        $instance = New-ExactDescriptorResourceInstance `
            -ClassName $ClassName `
            -Properties $Properties

        { $instance.Set() } | Should -Not -Throw
        $expectedSddl = $Properties.Sddl
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsAccessControlDscSecurityDescriptor `
            -Exactly `
            -Times 1 `
            -ParameterFilter {
                $Sddl -ceq $expectedSddl
            }
    }
}
