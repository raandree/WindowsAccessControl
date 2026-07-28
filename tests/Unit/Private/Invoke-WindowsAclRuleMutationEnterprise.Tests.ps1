BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Enterprise exact common-ACE removal' -Tag 'Unit', 'WindowsOnly' {
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
