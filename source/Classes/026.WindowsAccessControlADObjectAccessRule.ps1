<#
    .SYNOPSIS
        Ensures one exact explicit Active Directory access rule is present or
        absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry on
        a directory object, including the object type and inherited object type
        that scope a delegated right to one schema class or attribute set. The
        resource takes no credential, so the Local Configuration Manager binds
        LDAP as the node's own identity. Every write is confined to
        AllowedBaseDistinguishedName.

    .PARAMETER DistinguishedName
        The distinguished name of the directory object the rule applies to.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact directory rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER InheritanceType
        How the entry is inherited by objects below the target.

    .PARAMETER ObjectType
        The schema GUID the right is scoped to, or empty for no object scope.
        Anything else must be a real GUID, so a typo can never widen the managed
        entry to the whole object.

    .PARAMETER InheritedObjectType
        The schema GUID of the child class the entry is inherited by, or empty
        for no scope. The same GUID rule applies.

    .PARAMETER AllowedBaseDistinguishedName
        The subtree the configuration is allowed to write under. A target outside
        it is refused before anything is written.

    .PARAMETER Server
        The domain controller to bind over signed and sealed LDAP. When empty, a
        writable controller is discovered.

    .PARAMETER TimeoutSeconds
        The directory operation timeout in seconds.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlADObjectAccessRule {
    [DscProperty(Key)] [string]$DistinguishedName
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsActiveDirectoryRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)] [WindowsActiveDirectoryInheritance]$InheritanceType =
        [WindowsActiveDirectoryInheritance]::None
    [DscProperty(Key)] [string]$ObjectType = ''
    [DscProperty(Key)] [string]$InheritedObjectType = ''
    [DscProperty(Mandatory)] [string]$AllowedBaseDistinguishedName
    [DscProperty()] [string]$Server
    [DscProperty()] [int]$TimeoutSeconds = 10
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlADObjectAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily ADObject -Target $this.DistinguishedName `
            -Server $this.Server -TimeoutSeconds $this.TimeoutSeconds `
            -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType `
            -InheritanceType $this.InheritanceType `
            -ObjectTypeGuid $this.ParseGuid($this.ObjectType, 'ObjectType') `
            -InheritedObjectTypeGuid $this.ParseGuid(
                $this.InheritedObjectType, 'InheritedObjectType') `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlADObjectAccessRule]::new()
        $currentState.DistinguishedName = $this.DistinguishedName
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.InheritanceType = $this.InheritanceType
        $currentState.ObjectType = $this.ObjectType
        $currentState.InheritedObjectType = $this.InheritedObjectType
        $currentState.AllowedBaseDistinguishedName = $this.AllowedBaseDistinguishedName
        $currentState.Server = $this.Server
        $currentState.TimeoutSeconds = $this.TimeoutSeconds
        $currentState.Ensure = if ($present) {
            [WindowsAccessControlDscEnsure]::Present
        } else {
            [WindowsAccessControlDscEnsure]::Absent
        }
        $currentState.Reasons = $this.GetReasons($currentState.Ensure)
        return $currentState
    }

    [bool] Test() { return $this.Get().Reasons.Count -eq 0 }
    [void] Set() {
        Set-WindowsAccessControlDscAccessRule `
            -ObjectFamily ADObject -Target $this.DistinguishedName `
            -Server $this.Server `
            -AllowedBaseDistinguishedName $this.AllowedBaseDistinguishedName `
            -TimeoutSeconds $this.TimeoutSeconds -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType `
            -InheritanceType $this.InheritanceType `
            -ObjectTypeGuid $this.ParseGuid($this.ObjectType, 'ObjectType') `
            -InheritedObjectTypeGuid $this.ParseGuid(
                $this.InheritedObjectType, 'InheritedObjectType') `
            -Ensure $this.Ensure -ErrorAction Stop
    }
    # An empty key means "no object scope"; anything else must be a real GUID so
    # a typo can never widen the managed ACE to the whole object.
    [guid] ParseGuid([string]$Value, [string]$PropertyName) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return [guid]::Empty }
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($Value, [ref]$parsed)) {
            throw "$PropertyName must be empty or a GUID."
        }
        return $parsed
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact directory access rule on '$($this.DistinguishedName)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
