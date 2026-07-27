BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:isAdministrator = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $script:testSid = 'S-1-1-0'
    $script:createdServiceNames = [System.Collections.Generic.List[string]]::new()

    function New-WindowsAccessControlTestService {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This private Pester fixture creates a disposable service.'
        )]
        [CmdletBinding()]
        param()

        $script:serviceName = 'WacTest{0}' -f [guid]::NewGuid().ToString('N')
        $script:serviceDisplayName = 'Windows Access Control Test {0}' -f $script:serviceName
        if ($script:isAdministrator) {
            $binaryPath = "$env:SystemRoot\System32\cmd.exe /c exit 0"
            $output = & sc.exe create $script:serviceName 'binPath=' $binaryPath `
                'start=' 'demand' 'DisplayName=' $script:serviceDisplayName 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Disposable service creation failed: $output"
            }
            $script:createdServiceNames.Add($script:serviceName)
        }
    }

    function Remove-WindowsAccessControlTestService {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This private Pester fixture removes its disposable service.'
        )]
        [CmdletBinding()]
        param()

        if ($script:isAdministrator -and $script:serviceName) {
            & sc.exe delete $script:serviceName 2>&1 | Out-Null
            $null = $script:createdServiceNames.Remove($script:serviceName)
        }
    }
}

AfterAll {
    foreach ($serviceName in $script:createdServiceNames) {
        & sc.exe delete $serviceName 2>&1 | Out-Null
    }
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Service security descriptors' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        New-WindowsAccessControlTestService
    }

    AfterEach {
        Remove-WindowsAccessControlTestService
    }

    It 'Get-ServiceSecurityDescriptor should accept a local ServiceController pipeline object' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        $controller = Get-Service -Name $script:serviceName -ErrorAction Stop
        try {
            $result = $controller | Get-ServiceSecurityDescriptor
        } finally {
            $controller.Dispose()
        }

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.ServiceSecurityDescriptor'
        $result.ObjectType | Should -Be 'Service'
        $result.ServiceName | Should -Be $script:serviceName
        $result.BinarySecurityDescriptor.Length | Should -BeGreaterThan 0
    }

    It 'Set-ServiceSecurityDescriptor should round-trip one service DACL and honor WhatIf' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        $before = Get-ServiceSecurityDescriptor -Name $script:serviceName -Sections Access

        Set-ServiceSecurityDescriptor -Name $script:serviceName -Sddl $before.Sddl `
            -Sections Access -Confirm:$false
        Set-ServiceSecurityDescriptor -Name $script:serviceName `
            -Sddl 'D:(A;;CC;;;WD)' -Sections Access -WhatIf

        (Get-ServiceSecurityDescriptor -Name $script:serviceName -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }

    It 'Service target validation should reject display names and remote controllers' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        {
            Get-ServiceSecurityDescriptor `
                -Name $script:serviceDisplayName `
                -Sections Access `
                -ErrorAction Stop
        } |
            Should -Throw

        $controllerType = (Get-Service -Name $script:serviceName).GetType()
        $remote = [System.Activator]::CreateInstance(
            $controllerType,
            @($script:serviceName, 'remote-host')
        )
        try {
            {
                $remote | Get-ServiceSecurityDescriptor `
                    -Sections Access `
                    -ErrorAction Stop
            } |
                Should -Throw -ExpectedMessage '*remote*'
        } finally {
            $remote.Dispose()
        }
    }

    It 'Service Control Manager should be an explicit descriptor target' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Reading the SCM SACL requires elevation.'
            return
        }
        $before = Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access
        $audit = Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Audit

        $before.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.ServiceControlManagerSecurityDescriptor'
        $before.ObjectType | Should -Be 'ServiceControlManager'
        $audit.ObjectType | Should -Be 'ServiceControlManager'
        $audit.BinarySecurityDescriptor.Length | Should -BeGreaterThan 0
        Set-ServiceSecurityDescriptor -ServiceControlManager -Sddl $before.Sddl `
            -Sections Access -Confirm:$false
        Set-ServiceSecurityDescriptor -ServiceControlManager `
            -Sddl 'D:(A;;CC;;;WD)' `
            -Sections Access `
            -WhatIf
        (Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }
}

Describe 'Service access rules' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        New-WindowsAccessControlTestService
    }

    AfterEach {
        Remove-WindowsAccessControlTestService
    }

    It 'Add-ServiceAccessRule and Get-ServiceAccessRule should persist typed service rights' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -Confirm:$false

        $result = Get-ServiceAccessRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited

        $result | Should -HaveCount 1
        $result.AccessRights | Should -Be ([WindowsServiceRights]::QueryStatus)
        $result.AccessMask | Should -BeOfType ([uint64])
        $result.AccessControlType | Should -Be 'Allow'
        $result.AppliesTo | Should -BeNullOrEmpty
    }

    It 'Set-ServiceAccessRule should preserve the opposite access qualifier' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Stop -AccessControlType Deny -Confirm:$false
        Add-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -Confirm:$false

        Set-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Start -Confirm:$false

        $rules = @(Get-ServiceAccessRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited)
        $rules | Should -HaveCount 2
        ($rules | Where-Object AccessControlType -EQ Allow).AccessRights |
            Should -Be ([WindowsServiceRights]::Start)
        ($rules | Where-Object AccessControlType -EQ Deny).AccessRights |
            Should -Be ([WindowsServiceRights]::Stop)
    }

    It 'Remove-ServiceAccessRule should remove an exact pipeline rule' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -Confirm:$false
        $rule = Get-ServiceAccessRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited

        $rule | Remove-ServiceAccessRule -Confirm:$false

        Get-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Clear-ServiceAccessRule should remove selected explicit account rules' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -Confirm:$false

        Clear-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -Confirm:$false

        Get-ServiceAccessRule -Name $script:serviceName -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Get-ServiceAccessRule should expose typed SCM rights' {
        $rules = @(Get-ServiceAccessRule -ServiceControlManager)

        $rules | Should -Not -BeNullOrEmpty
        $rules[0].PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.ServiceControlManagerAccessRule'
        $rules[0].AccessRights | Should -BeOfType ([WindowsServiceControlManagerRights])
        $rules[0].AccessMask | Should -BeOfType ([uint64])
    }
}

Describe 'Service audit rules' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        New-WindowsAccessControlTestService
    }

    AfterEach {
        Remove-WindowsAccessControlTestService
    }

    It 'Add-ServiceAuditRule and Get-ServiceAuditRule should persist a SACL rule' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Start -AuditFlags Failure -Confirm:$false

        $result = @(Get-ServiceAuditRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited | Where-Object {
                $_.AccessRights -eq [WindowsServiceRights]::Start
            })

        $result | Should -HaveCount 1
        $result.AuditFlags | Should -Be 'Failure'
        $result.AccessRights | Should -Be ([WindowsServiceRights]::Start)
    }

    It 'Set-ServiceAuditRule should preserve opposite audit flags' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -AuditFlags Success -Confirm:$false
        Add-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights QueryStatus -AuditFlags Failure -Confirm:$false

        Set-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Start -AuditFlags Failure -Confirm:$false

        $rules = @(Get-ServiceAuditRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited)
        $rules | Should -HaveCount 2
        ($rules | Where-Object AuditFlags -EQ Success).AccessRights |
            Should -Be ([WindowsServiceRights]::QueryStatus)
        ($rules | Where-Object AuditFlags -EQ Failure).AccessRights |
            Should -Be ([WindowsServiceRights]::Start)
    }

    It 'Remove-ServiceAuditRule should remove an exact pipeline rule' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Start -AuditFlags Failure -Confirm:$false
        $rule = Get-ServiceAuditRule -Name $script:serviceName `
            -Account $script:testSid -ExcludeInherited

        $rule | Remove-ServiceAuditRule -Confirm:$false

        Get-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Clear-ServiceAuditRule should remove selected explicit account rules' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        Add-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ServiceRights Start -AuditFlags Failure -Confirm:$false

        Clear-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -Confirm:$false

        Get-ServiceAuditRule -Name $script:serviceName -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }
}
