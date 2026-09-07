BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
}

Describe 'Enterprise exact common-ACE removal' -Tag 'Unit', 'WindowsOnly' {
    It 'Should preserve <Case> when removing a different native ACE' -ForEach @(
        @{ Case = 'a callback ACE beside a plain allow ACE'; RuleType = 'Access'; Kind = 'CallbackType' }
        @{ Case = 'a callback ACE with another payload'; RuleType = 'Access'; Kind = 'CallbackPayload' }
        @{ Case = 'an object ACE with another GUID'; RuleType = 'Access'; Kind = 'ObjectGuid' }
        @{ Case = 'a callback audit ACE beside a plain audit ACE'; RuleType = 'Audit'; Kind = 'CallbackType' }
        @{ Case = 'a callback audit ACE with another payload'; RuleType = 'Audit'; Kind = 'CallbackPayload' }
    ) {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $flags = if ($RuleType -eq 'Audit') {
            [Security.AccessControl.AceFlags]::SuccessfulAccess
        } else {
            [Security.AccessControl.AceFlags]::None
        }
        $qualifier = if ($RuleType -eq 'Audit') {
            [Security.AccessControl.AceQualifier]::SystemAudit
        } else {
            [Security.AccessControl.AceQualifier]::AccessAllowed
        }
        if ($Kind -eq 'ObjectGuid') {
            $selected = [Security.AccessControl.ObjectAce]::new(
                $flags, $qualifier, 4, $sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                [guid]'11111111-1111-1111-1111-111111111111', [guid]::Empty, $false, $null
            )
            $unrelated = [Security.AccessControl.ObjectAce]::new(
                $flags, $qualifier, 4, $sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                [guid]'22222222-2222-2222-2222-222222222222', [guid]::Empty, $false, $null
            )
        } else {
            $selected = [Security.AccessControl.CommonAce]::new(
                $flags, $qualifier, 4, $sid, ($Kind -eq 'CallbackPayload'),
                $(if ($Kind -eq 'CallbackPayload') { [byte[]]@(1, 2, 3, 4) } else { $null })
            )
            $unrelated = [Security.AccessControl.CommonAce]::new(
                $flags, $qualifier, 4, $sid, $true, [byte[]]@(5, 6, 7, 8)
            )
        }
        $acl = [Security.AccessControl.RawAcl]::new(4, 2)
        $acl.InsertAce(0, $selected)
        $acl.InsertAce(1, $unrelated)
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:')
        if ($RuleType -eq 'Audit') {
            $descriptor.SystemAcl = $acl
            $descriptor.SetFlags($descriptor.ControlFlags -bor [Security.AccessControl.ControlFlags]::SystemAclPresent)
        } else {
            $descriptor.DiscretionaryAcl = $acl
        }
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)

        $result = & $script:module {
            param($Bytes, $Selected, $RuleType)
            Invoke-WindowsAclRuleMutation -SecurityDescriptor $Bytes -RuleType $RuleType `
                -Operation Remove -NativeAce $Selected
        } $bytes $selected $RuleType

        $after = [Security.AccessControl.RawSecurityDescriptor]::new($result, 0)
        $remaining = if ($RuleType -eq 'Audit') { $after.SystemAcl } else { $after.DiscretionaryAcl }
        $remaining | Should -HaveCount 1
        $remaining[0].Equals($unrelated) | Should -BeTrue
        $after.Owner.Value | Should -BeExactly 'S-1-5-18'
        $after.Group.Value | Should -BeExactly 'S-1-5-18'
    }

    It 'Should treat exact removal of an absent SMB ACE as an idempotent no-op' {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $acl = [Security.AccessControl.RawAcl]::new(
            [Security.AccessControl.GenericAcl]::AclRevision,
            0
        )
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
            $sid,
            $sid,
            $null,
            $acl
        )
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        $absentAce = [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]::None,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            [int][WindowsSmbShareRights]::Read,
            $sid,
            $false,
            $null
        )

        $result = & $script:module {
            param($Descriptor, $NativeAce)
            Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $Descriptor `
                -RuleType Access `
                -Operation Remove `
                -NativeAce $NativeAce
        } $bytes $absentAce

        [Convert]::ToBase64String($result) |
            Should -BeExactly ([Convert]::ToBase64String($bytes))
    }
}
