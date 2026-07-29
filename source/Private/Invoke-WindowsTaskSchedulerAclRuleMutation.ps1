function Invoke-WindowsTaskSchedulerAclRuleMutation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this persistence boundary.'
    )]
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
        [System.Security.AccessControl.AceFlags]$AceFlags =
            [System.Security.AccessControl.AceFlags]::None,

        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $currentDescriptor = Get-WindowsTaskSchedulerSecurityDescriptor -Target $Target
    $descriptor = $currentDescriptor
    if ($Operation -eq 'Add') {
        foreach ($sid in $SecurityIdentifier) {
            $descriptor = Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $descriptor `
                -RuleType Access `
                -Operation Add `
                -SecurityIdentifier $sid `
                -AccessMask $AccessMask `
                -AccessControlType $AccessControlType `
                -AceFlags $AceFlags `
                -MatchAceFlags
        }
    }
    else {
        $descriptor = Invoke-WindowsAclRuleMutation `
            -SecurityDescriptor $descriptor `
            -RuleType Access `
            -Operation Remove `
            -NativeAce $NativeAce
    }

    Set-WindowsTaskSchedulerSecurityDescriptor `
        -Target $Target `
        -SecurityDescriptor $descriptor `
        -ExpectedCurrentSecurityDescriptor $currentDescriptor
}
