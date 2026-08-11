function New-NTFSFileSystemRule {
    [CmdletBinding(DefaultParameterSetName = 'Access')]
    [OutputType([System.Security.AccessControl.AuthorizationRule])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier,

        [Parameter(Mandatory)]
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter()]
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags =
            [System.Security.AccessControl.InheritanceFlags]::None,

        [Parameter()]
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags =
            [System.Security.AccessControl.PropagationFlags]::None,

        [Parameter(Mandatory, ParameterSetName = 'Access')]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [Parameter(Mandatory, ParameterSetName = 'Audit')]
        [System.Security.AccessControl.AuditFlags]$AuditFlags
    )

    $mask = [int]$AccessRights
    $isNameableMask = $mask -ge 0 -and
        $mask -le [int][System.Security.AccessControl.FileSystemRights]::FullControl

    if ($isNameableMask) {
        # The public constructors normalize Synchronize for allow and deny
        # rules, so a mask the enum can name keeps the framework's own
        # behavior.
        if ($PSCmdlet.ParameterSetName -eq 'Audit') {
            return [System.Security.AccessControl.FileSystemAuditRule]::new(
                $SecurityIdentifier,
                $AccessRights,
                $InheritanceFlags,
                $PropagationFlags,
                $AuditFlags
            )
        }
        return [System.Security.AccessControl.FileSystemAccessRule]::new(
            $SecurityIdentifier,
            $AccessRights,
            $InheritanceFlags,
            $PropagationFlags,
            $AccessControlType
        )
    }

    # A mask carrying GENERIC_*, ACCESS_SYSTEM_SECURITY, or MAXIMUM_ALLOWED is
    # outside the range the public rule constructors accept, yet Windows stores
    # such entries. The rule factory takes the raw mask verbatim, which is also
    # what an exact match against the stored entry requires.
    $factory = [System.Security.AccessControl.DirectorySecurity]::new()
    if ($PSCmdlet.ParameterSetName -eq 'Audit') {
        return $factory.AuditRuleFactory(
            $SecurityIdentifier,
            $mask,
            $false,
            $InheritanceFlags,
            $PropagationFlags,
            $AuditFlags
        )
    }
    $factory.AccessRuleFactory(
        $SecurityIdentifier,
        $mask,
        $false,
        $InheritanceFlags,
        $PropagationFlags,
        $AccessControlType
    )
}
