BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl

    function New-AccessRuleDscResourceInstance {
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

    function New-AccessRuleDscTestService {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This fixture creates one disposable service.'
        )]
        param()

        $name = 'WacDscRule{0}' -f [guid]::NewGuid().ToString('N')
        $binaryPath = "$env:SystemRoot\System32\cmd.exe /c exit 0"
        $output = & sc.exe create $name 'binPath=' $binaryPath 'start=' 'demand' 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Disposable service creation failed: $output"
        }
        $name
    }
}

AfterAll {
    Get-Service -Name 'WacDscRule*' -ErrorAction SilentlyContinue |
        ForEach-Object { & sc.exe delete $_.Name 2>&1 | Out-Null }
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Access-rule presence DSC resources' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    It 'Should converge one NTFS access rule without removing unrelated rules' {
        $path = Join-Path $TestDrive 'rule-presence.txt'
        Set-Content -LiteralPath $path -Value 'test'
        $managedSid = 'S-1-5-21-4242424242-4242424242-4242424242-5201'
        $unrelatedSid = 'S-1-5-21-4242424242-4242424242-4242424242-5202'
        Add-NTFSAccessRule -LiteralPath $path -Account $unrelatedSid `
            -AccessRights Write -Confirm:$false
        $resource = New-AccessRuleDscResourceInstance `
            -ClassName WindowsAccessControlNtfsAccessRule `
            -Properties @{
                Path = $path; Account = $managedSid; AccessRights = 'Read'
                AccessControlType = 'Allow'; AppliesTo = 'ThisFolderOnly'
            }

        $resource.Test() | Should -BeFalse
        $resource.Set()
        $resource.Test() | Should -BeTrue
        $resource.Ensure = 'Absent'
        $resource.Test() | Should -BeFalse
        $resource.Set()
        $resource.Test() | Should -BeTrue
        Get-NTFSAccessRule -LiteralPath $path -Account $unrelatedSid -ExcludeInherited |
            Should -Not -BeNullOrEmpty
    }

    It 'Should converge one registry-key access rule' {
        $path = "HKCU:\Software\WindowsAccessControlDscRuleTest\$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -Path $path -Force
        try {
            $resource = New-AccessRuleDscResourceInstance `
                -ClassName WindowsAccessControlRegistryKeyAccessRule `
                -Properties @{
                    Path = $path; RegistryView = 'Default'; Account = 'S-1-1-0'
                    AccessRights = 'ReadKey'; AccessControlType = 'Allow'
                    AppliesTo = 'ThisKeyOnly'
                }
            $resource.Test() | Should -BeFalse
            $resource.Set()
            $resource.Test() | Should -BeTrue
            $resource.Ensure = 'Absent'
            $resource.Set()
            $resource.Test() | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should converge one named-service access rule' {
        $serviceName = New-AccessRuleDscTestService
        try {
            $resource = New-AccessRuleDscResourceInstance `
                -ClassName WindowsAccessControlServiceAccessRule `
                -Properties @{
                    Name = $serviceName; Account = 'S-1-1-0'
                    ServiceRights = 'QueryStatus'; AccessControlType = 'Allow'
                }
            $resource.Test() | Should -BeFalse
            $resource.Set()
            $resource.Test() | Should -BeTrue
            $resource.Ensure = 'Absent'
            $resource.Set()
            $resource.Test() | Should -BeTrue
        } finally {
            & sc.exe delete $serviceName 2>&1 | Out-Null
        }
    }

    It 'Should converge one SCM access rule and restore the original DACL' {
        $before = Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access
        try {
            $resource = New-AccessRuleDscResourceInstance `
                -ClassName WindowsAccessControlServiceControlManagerAccessRule `
                -Properties @{
                    Account = 'S-1-5-21-4242424242-4242424242-4242424242-5203'
                    ControlManagerRights = 'Connect'; AccessControlType = 'Allow'
                }
            $resource.Test() | Should -BeFalse
            $resource.Set()
            $resource.Test() | Should -BeTrue
            $resource.Ensure = 'Absent'
            $resource.Set()
            $resource.Test() | Should -BeTrue
        } finally {
            Set-ServiceSecurityDescriptor -ServiceControlManager `
                -Sections Access -Sddl $before.Sddl -Confirm:$false
        }
        (Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }

    It 'Should converge one pinned-process access rule and restore the original DACL' {
        $before = Get-ProcessSecurityDescriptor -InputObject $PID -Sections Access
        try {
            $resource = New-AccessRuleDscResourceInstance `
                -ClassName WindowsAccessControlProcessAccessRule `
                -Properties @{
                    ProcessId = $before.ProcessId
                    CreationTimeFileTime = $before.CreationTimeFileTime
                    Account = 'S-1-5-21-4242424242-4242424242-4242424242-5204'
                    ProcessRights = 'QueryLimitedInformation'
                    AccessControlType = 'Allow'
                }
            $resource.Test() | Should -BeFalse
            $resource.Set()
            $resource.Test() | Should -BeTrue
            $resource.Ensure = 'Absent'
            $resource.Set()
            $resource.Test() | Should -BeTrue
        } finally {
            Set-ProcessSecurityDescriptor -InputObject $before -Sections Access `
                -Sddl $before.Sddl -Confirm:$false
        }
        (Get-ProcessSecurityDescriptor -InputObject $before -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }
}
