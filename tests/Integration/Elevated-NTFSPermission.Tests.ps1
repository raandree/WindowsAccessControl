# Privilege-gated SACL and arbitrary-owner acceptance (FR-6, FR-7, FR-8, FR-10, NFR-7).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:enabledPrivileges = [System.Collections.Generic.List[string]]::new()
    $script:privilegeReasons = @{}
    $tokenPrivileges = @(Get-NTFSPrivilege)

    foreach ($privilegeName in 'SeSecurityPrivilege', 'SeRestorePrivilege') {
        $privilege = $tokenPrivileges | Where-Object Name -eq $privilegeName
        if (-not $privilege) {
            $script:privilegeReasons[$privilegeName] = "The process token does not contain $privilegeName."
            continue
        }
        if ($privilege -and -not $privilege.Enabled) {
            try {
                Enable-NTFSPrivilege -Name $privilegeName -Confirm:$false
                $script:enabledPrivileges.Add($privilegeName)
            } catch {
                $script:privilegeReasons[$privilegeName] =
                    "$privilegeName could not be enabled: $($_.Exception.Message)"
            }
        }
    }

    $script:hasSecurityPrivilege = Test-NTFSPrivilege -Name 'SeSecurityPrivilege'
    $script:hasRestorePrivilege = Test-NTFSPrivilege -Name 'SeRestorePrivilege'
    if (-not $script:hasSecurityPrivilege -and
        -not $script:privilegeReasons.ContainsKey('SeSecurityPrivilege')) {
        $script:privilegeReasons.SeSecurityPrivilege = 'SeSecurityPrivilege is not enabled.'
    }
    if (-not $script:hasRestorePrivilege -and
        -not $script:privilegeReasons.ContainsKey('SeRestorePrivilege')) {
        $script:privilegeReasons.SeRestorePrivilege = 'SeRestorePrivilege is not enabled.'
    }
}

AfterAll {
    foreach ($privilegeName in $script:enabledPrivileges) {
        Disable-NTFSPrivilege -Name $privilegeName -Confirm:$false
    }
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Elevated NTFSPermission acceptance' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    It 'Should add and query a real SACL rule' {
        if (-not $script:hasSecurityPrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeSecurityPrivilege
            return
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'audit-add-get.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = $script:currentSid
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }
        $getParameters = @{
            LiteralPath     = $testFile
            Account         = $script:currentSid
            ExcludeInherited = $true
        }

        Add-NTFSAuditRule @addParameters
        $storedRule = Get-NTFSAuditRule @getParameters

        $storedRule | Should -Not -BeNullOrEmpty
        $storedRule.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
    }

    It 'Should replace and remove a real SACL rule' {
        if (-not $script:hasSecurityPrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeSecurityPrivilege
            return
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'audit-set-remove.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $ruleParameters = @{
            LiteralPath  = $testFile
            Account      = $script:currentSid
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }
        Add-NTFSAuditRule @ruleParameters

        $ruleParameters.AccessRights = 'Write'
        Set-NTFSAuditRule @ruleParameters
        $getParameters = @{
            LiteralPath      = $testFile
            Account          = $script:currentSid
            ExcludeInherited = $true
        }
        $storedRule = Get-NTFSAuditRule @getParameters
        $storedRule | Remove-NTFSAuditRule -Confirm:$false

        ($storedRule.AccessRights -band [System.Security.AccessControl.FileSystemRights]::Write) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Write)
        Get-NTFSAuditRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should clear multiple real SACL rules' {
        if (-not $script:hasSecurityPrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeSecurityPrivilege
            return
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'audit-clear.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $accounts = @($script:currentSid, 'S-1-1-0')
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = $accounts
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }
        Add-NTFSAuditRule @addParameters

        Clear-NTFSAuditRule -LiteralPath $testFile -Confirm:$false

        Get-NTFSAuditRule -LiteralPath $testFile -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Should remove explicit SACL rules while enabling audit inheritance' {
        if (-not $script:hasSecurityPrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeSecurityPrivilege
            return
        }
        $parent = Join-Path -Path $TestDrive -ChildPath 'audit-inheritance-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = $script:currentSid
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }
        Add-NTFSAuditRule @addParameters
        Disable-NTFSItemInheritance -LiteralPath $testFile -Section Audit -Confirm:$false
        $enableParameters = @{
            LiteralPath         = $testFile
            Section             = 'Audit'
            RemoveExplicitRules = $true
            Confirm             = $false
        }

        Enable-NTFSItemInheritance @enableParameters

        (Get-NTFSItemInheritance -LiteralPath $testFile -Section Audit).AuditInheritanceEnabled |
            Should -BeTrue
        Get-NTFSAuditRule -LiteralPath $testFile -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Should back up and restore a real SACL' {
        if (-not $script:hasSecurityPrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeSecurityPrivilege
            return
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'audit-backup-restore.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'audit-backup.json'
        Set-Content -LiteralPath $testFile -Value 'test'
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = $script:currentSid
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            Confirm      = $false
        }
        Add-NTFSAuditRule @addParameters
        $backupParameters = @{
            LiteralPath    = $testFile
            DestinationPath = $backupPath
            Sections       = 'Audit'
            Confirm        = $false
        }
        Backup-NTFSItemSecurityDescriptor @backupParameters
        Clear-NTFSAuditRule -LiteralPath $testFile -Confirm:$false

        Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false

        Get-NTFSAuditRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited |
            Should -Not -BeNullOrEmpty
    }

    It 'Should assign an arbitrary owner with SeRestorePrivilege' {
        if (-not $script:hasRestorePrivilege) {
            Set-ItResult -Skipped -Because $script:privilegeReasons.SeRestorePrivilege
            return
        }
        $testFile = Join-Path -Path $TestDrive -ChildPath 'arbitrary-owner.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $originalOwner = Get-NTFSItemOwner -LiteralPath $testFile
        $targetSid = if ($originalOwner.SID -eq 'S-1-5-32-544') {
            'S-1-5-32-545'
        } else {
            'S-1-5-32-544'
        }

        try {
            Set-NTFSItemOwner -LiteralPath $testFile -Account $targetSid -Confirm:$false

            (Get-NTFSItemOwner -LiteralPath $testFile).SID | Should -Be $targetSid
        } finally {
            Set-NTFSItemOwner -LiteralPath $testFile -Account $originalOwner.SID -Confirm:$false
        }
    }
}
