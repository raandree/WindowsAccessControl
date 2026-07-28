function Invoke-WindowsSmbShareAclRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Remove')]
        [string]$Operation,

        [Parameter()]
        [System.Security.Principal.SecurityIdentifier[]]$SecurityIdentifier,

        [Parameter()]
        [int]$AccessMask,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $getParameters = @{
        NativePath       = $Target.NativePath
        NativeObjectType = $Target.NativeObjectType
        Sections         = [WindowsSecurityDescriptorSection]::Access
    }
    $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getParameters
    $descriptor = $currentDescriptor
    if ($Operation -eq 'Add') {
        foreach ($sid in $SecurityIdentifier) {
            $descriptor = Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $descriptor `
                -RuleType Access `
                -Operation Add `
                -SecurityIdentifier $sid `
                -AccessMask $AccessMask `
                -AccessControlType $AccessControlType
        }
    }
    else {
        $descriptor = Invoke-WindowsAclRuleMutation `
            -SecurityDescriptor $descriptor `
            -RuleType Access `
            -Operation Remove `
            -NativeAce $NativeAce
    }

    Set-WindowsSmbShareSecurityDescriptor `
        -Target $Target `
        -SecurityDescriptor $descriptor `
        -CurrentSecurityDescriptor $currentDescriptor
    $descriptor
}
