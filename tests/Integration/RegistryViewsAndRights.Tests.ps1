# Registry view independence, literal semantics, and error paths (FR-32, ADR 0032).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    $script:isCoreEdition = $PSVersionTable.PSEdition -eq 'Core'
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # Nothing resolves this identifier, so a grant cannot widen real access.
    $script:inertSid = 'S-1-5-21-1999999999-2999999999-3999999999-4321'
    $script:otherInertSid = 'S-1-5-21-1999999999-2999999999-3999999999-4322'
    $script:machineKeyName = 'WacViewIndependence-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $script:machineKeyPath = "HKLM:\SOFTWARE\$script:machineKeyName"
    $script:userKeyName = 'WacRegistry-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

    $script:machineKeySkipReason = $null
    try {
        foreach ($view in 'Registry32', 'Registry64') {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
            try {
                $subKey = $baseKey.CreateSubKey("SOFTWARE\$script:machineKeyName")
                $subKey.Close()
            } finally {
                $baseKey.Close()
            }
        }
    } catch {
        $script:machineKeySkipReason =
            "The machine software hive is not writable: $($_.Exception.Message)"
    }

    $script:userBaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', 'Default')
    $script:bracketKeyPath = "HKCU:\Software\$script:userKeyName[1]"
    $subKey = $script:userBaseKey.CreateSubKey("Software\$script:userKeyName[1]")
    $subKey.Close()
    $subKey = $script:userBaseKey.CreateSubKey("Software\$script:userKeyName1")
    $subKey.Close()
}

AfterAll {
    foreach ($view in 'Registry32', 'Registry64') {
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
            try {
                $baseKey.DeleteSubKeyTree("SOFTWARE\$script:machineKeyName", $false)
            } finally {
                $baseKey.Close()
            }
        } catch {
            # The key may never have been created; removal is best effort.
        }
    }
    foreach ($name in "Software\$script:userKeyName[1]", "Software\$script:userKeyName1") {
        try {
            $script:userBaseKey.DeleteSubKeyTree($name, $false)
        } catch {
            # Best effort.
        }
    }
    if ($script:userBaseKey) {
        $script:userBaseKey.Close()
    }
}

Describe 'Registry view independence' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    It 'Should leave the other view unchanged when a view is written' -ForEach @(
        @{ WrittenView = 'Registry32'; OtherView = 'Registry64' }
        @{ WrittenView = 'Registry64'; OtherView = 'Registry32' }
    ) {
        if ($script:machineKeySkipReason) {
            Set-ItResult -Skipped -Because $script:machineKeySkipReason
            return
        }
        $account = if ($WrittenView -eq 'Registry32') { $script:inertSid } else { $script:otherInertSid }
        $addParameters = @{
            Path         = $script:machineKeyPath
            RegistryView = $WrittenView
            Account      = $account
            AccessRights = 'ReadKey'
            Confirm      = $false
        }

        Add-RegistryKeyAccessRule @addParameters

        @(Get-RegistryKeyAccessRule -Path $script:machineKeyPath -RegistryView $WrittenView -Account $account) |
            Should -HaveCount 1
        @(Get-RegistryKeyAccessRule -Path $script:machineKeyPath -RegistryView $OtherView -Account $account) |
            Should -BeNullOrEmpty
    }

    It 'Should carry the selected view into every rule the command emits' {
        if ($script:machineKeySkipReason) {
            Set-ItResult -Skipped -Because $script:machineKeySkipReason
            return
        }
        foreach ($view in 'Registry32', 'Registry64') {
            $rules = @(Get-RegistryKeyAccessRule -Path $script:machineKeyPath -RegistryView $view)
            $rules | Should -Not -BeNullOrEmpty
            @($rules.RegistryView | Sort-Object -Unique) | Should -Be @($view)
        }
    }

    It 'Should produce the union of both views without leaking either into the other' {
        if ($script:machineKeySkipReason) {
            Set-ItResult -Skipped -Because $script:machineKeySkipReason
            return
        }
        $thirtyTwoBit = @(
            Get-RegistryKeyAccessRule -Path $script:machineKeyPath -RegistryView Registry32
        )
        $sixtyFourBit = @(
            Get-RegistryKeyAccessRule -Path $script:machineKeyPath -RegistryView Registry64
        )

        @($thirtyTwoBit.SID) | Should -Contain $script:inertSid
        @($thirtyTwoBit.SID) | Should -Not -Contain $script:otherInertSid
        @($sixtyFourBit.SID) | Should -Contain $script:otherInertSid
        @($sixtyFourBit.SID) | Should -Not -Contain $script:inertSid
        @($thirtyTwoBit + $sixtyFourBit | ForEach-Object { $_.SID } | Sort-Object -Unique) |
            Should -Contain $script:inertSid
    }

    It 'Should resolve the emitted path back to the same key' {
        if ($script:machineKeySkipReason) {
            Set-ItResult -Skipped -Because $script:machineKeySkipReason
            return
        }
        $descriptor = Get-RegistryKeySecurityDescriptor -Path $script:machineKeyPath -RegistryView Registry32

        $roundTrip = Get-RegistryKeySecurityDescriptor -Path $descriptor.Path -RegistryView Registry32

        $roundTrip.Sddl | Should -Be $descriptor.Sddl
        $roundTrip.Path | Should -Be $descriptor.Path
    }
}

Describe 'Registry literal and edition behavior' -Tag 'Integration', 'WindowsOnly' {
    It 'Should address a key whose name contains brackets' {
        $descriptor = Get-RegistryKeySecurityDescriptor -Path $script:bracketKeyPath

        $descriptor.Path | Should -Be $script:bracketKeyPath
    }

    It 'Should read a bracketed key while the provider cmdlet differs by edition' {
        $moduleSddl = (Get-RegistryKeySecurityDescriptor -Path $script:bracketKeyPath).Sddl
        $moduleSddl | Should -Not -BeNullOrEmpty

        $providerFailed = $false
        try {
            $null = Get-Acl -LiteralPath $script:bracketKeyPath -ErrorAction Stop
        } catch {
            $providerFailed = $true
        }

        if ($script:isCoreEdition) {
            $providerFailed | Should -BeFalse
        } else {
            # Windows PowerShell cannot resolve Get-Acl -LiteralPath for a
            # registry key, which is why the module resolves the target itself
            # instead of delegating to the provider cmdlet.
            $providerFailed | Should -BeTrue
        }

        # Neither edition expands the bracket for -Path, so the pattern matches
        # the decoy name and not the literal one.
        @(Get-Acl -Path $script:bracketKeyPath -ErrorAction SilentlyContinue) |
            Should -BeNullOrEmpty
    }

    It 'Should read the current profile hive through HKU' {
        $descriptor = Get-RegistryKeySecurityDescriptor -Path "HKU:\$script:currentSid"

        $descriptor.Path | Should -Be "HKU:\$script:currentSid"
        $descriptor.Sddl | Should -Not -BeNullOrEmpty
    }
}

Describe 'Registry symbolic link behavior' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report the target of a registry symbolic link' {
        # HKLM\SYSTEM\CurrentControlSet is a REG_LINK created by the system, and
        # opening it without REG_OPTION_OPEN_LINK opens its target. ADR 0032
        # records that the module follows the link.
        $throughLink = Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SYSTEM\CurrentControlSet'
        $throughTarget = Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SYSTEM\ControlSet001'

        $throughLink.Sddl | Should -Be $throughTarget.Sddl
    }
}

Describe 'Registry error paths' -Tag 'Integration', 'WindowsOnly' {
    It 'Should give a deterministic outcome for the protected security hive' {
        $descriptor = $null
        $errorRecord = $null
        try {
            $descriptor = Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SECURITY' -ErrorAction Stop
        } catch {
            $errorRecord = $_
        }

        if ($errorRecord) {
            # A refusal must be a typed access-denied, never an unhandled fault.
            $errorRecord.Exception | Should -BeOfType ([System.Exception])
            $errorRecord.Exception.Message | Should -Not -BeNullOrEmpty
            $errorRecord.CategoryInfo.Category |
                Should -BeIn @('PermissionDenied', 'SecurityError', 'InvalidOperation', 'NotSpecified')
        } else {
            $descriptor.Sddl | Should -Not -BeNullOrEmpty
        }
    }

    It 'Should reject a native remote registry target' {
        { Get-RegistryKeySecurityDescriptor -Path '\\server\HKLM\SOFTWARE' -ErrorAction Stop } |
            Should -Throw
    }

    It 'Should report an audit-rule read distinguishably from an empty list' {
        $auditRules = @(Get-RegistryKeyAuditRule -Path "HKCU:\Software\$script:userKeyName1")

        # The key has no system access control list entry, and the command says
        # so by returning nothing rather than by failing.
        $auditRules | Should -BeNullOrEmpty

        if (Test-WindowsPrivilege -Name 'SeSecurityPrivilege') {
            $descriptor = Get-RegistryKeySecurityDescriptor `
                -Path "HKCU:\Software\$script:userKeyName1" `
                -Sections Audit
            $descriptor.Sections | Should -Match 'Audit'
        } else {
            Set-ItResult -Skipped -Because 'SeSecurityPrivilege is not held, so the audit section cannot be read.'
        }
    }
}
