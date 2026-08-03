BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'

    # NFR-7: the audit section needs SeSecurityPrivilege in the token, so the
    # scenario stays discovered and reports why it was skipped.
    $script:auditSkipReason = $null
    if (-not (@(Get-WindowsPrivilege).Name -contains 'SeSecurityPrivilege')) {
        $script:auditSkipReason =
            'The process token does not contain SeSecurityPrivilege, which the audit section requires.'
    }

    function New-ExactDscResourceInstance {
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

Describe 'Exact security descriptor DSC resources' -Tag 'Integration', 'WindowsOnly' {
    It 'Should reconverge an NTFS DACL' {
        $path = Join-Path $TestDrive 'exact-dsc.txt'
        Set-Content -LiteralPath $path -Value 'test'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $path `
            -Sections Access
        $resource = New-ExactDscResourceInstance `
            -ClassName WindowsAccessControlNtfsSecurityDescriptor `
            -Properties @{
                Path = $path
                Sections = 'Access'
                Sddl = $descriptor.Sddl
            }

        $resource.Test() | Should -BeTrue
        Add-NTFSAccessRule `
            -LiteralPath $path `
            -Account 'S-1-5-21-4242424242-4242424242-4242424242-5101' `
            -AccessRights Read `
            -Confirm:$false
        $resource.Test() | Should -BeFalse

        $resource.Set()

        $resource.Test() | Should -BeTrue
    }

    It 'Should reconverge all NTFS descriptor sections together' {
        if ($script:auditSkipReason) {
            Set-ItResult -Skipped -Because $script:auditSkipReason
            return
        }
        $path = Join-Path $TestDrive 'exact-dsc-all.txt'
        Set-Content -LiteralPath $path -Value 'test'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $path `
            -Sections All
        $resource = New-ExactDscResourceInstance `
            -ClassName WindowsAccessControlNtfsSecurityDescriptor `
            -Properties @{
                Path = $path
                Sections = 'All'
                Sddl = $descriptor.Sddl
            }

        Add-NTFSAccessRule `
            -LiteralPath $path `
            -Account 'S-1-5-21-4242424242-4242424242-4242424242-5103' `
            -AccessRights Read `
            -Confirm:$false
        Add-NTFSAuditRule `
            -LiteralPath $path `
            -Account 'S-1-5-21-4242424242-4242424242-4242424242-5104' `
            -AccessRights Write `
            -AuditFlags Failure `
            -Confirm:$false
        $resource.Test() | Should -BeFalse

        $resource.Set()

        $resource.Test() | Should -BeTrue
    }

    It 'Should reconverge a registry-key DACL' {
        $testId = [guid]::NewGuid().ToString('N')
        $path = "HKCU:\Software\WindowsAccessControlDscTest\$testId"
        $null = New-Item -Path $path -Force -ErrorAction Stop
        try {
            $descriptor = Get-RegistryKeySecurityDescriptor `
                -Path $path `
                -RegistryView Default `
                -Sections Access
            $resource = New-ExactDscResourceInstance `
                -ClassName WindowsAccessControlRegistryKeySecurityDescriptor `
                -Properties @{
                    Path = $path
                    RegistryView = 'Default'
                    Sections = 'Access'
                    Sddl = $descriptor.Sddl
                }

            $resource.Test() | Should -BeTrue
            Add-RegistryKeyAccessRule `
                -Path $path `
                -Account 'S-1-5-21-4242424242-4242424242-4242424242-5102' `
                -AccessRights ReadKey `
                -Confirm:$false
            $resource.Test() | Should -BeFalse

            $resource.Set()

            $resource.Test() | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should evaluate and no-op a named service descriptor' {
        $serviceName = 'EventLog'
        $descriptor = Get-ServiceSecurityDescriptor `
            -Name $serviceName `
            -Sections Access
        $resource = New-ExactDscResourceInstance `
            -ClassName WindowsAccessControlServiceSecurityDescriptor `
            -Properties @{
                Name = $serviceName
                Sections = 'Access'
                Sddl = $descriptor.Sddl
            }

        $resource.Test() | Should -BeTrue
    }

    It 'Should evaluate and no-op the Service Control Manager descriptor' {
        $descriptor = Get-ServiceSecurityDescriptor `
            -ServiceControlManager `
            -Sections Access
        $resource = New-ExactDscResourceInstance `
            -ClassName WindowsAccessControlServiceControlManagerSecurityDescriptor `
            -Properties @{
                Sections = 'Access'
                Sddl = $descriptor.Sddl
            }

        $resource.Test() | Should -BeTrue
    }

    It 'Should evaluate and no-op a pinned process descriptor' {
        $descriptor = Get-ProcessSecurityDescriptor `
            -InputObject $PID `
            -Sections Access
        $resource = New-ExactDscResourceInstance `
            -ClassName WindowsAccessControlProcessSecurityDescriptor `
            -Properties @{
                ProcessId = $descriptor.ProcessId
                CreationTimeFileTime = $descriptor.CreationTimeFileTime
                Sections = 'Access'
                Sddl = $descriptor.Sddl
            }

        $resource.Test() | Should -BeTrue
        { $resource.Set() } | Should -Not -Throw
        $resource.Test() | Should -BeTrue
    }
}
