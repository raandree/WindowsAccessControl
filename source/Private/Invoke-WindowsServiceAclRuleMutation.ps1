function Invoke-WindowsServiceAclRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Set', 'Remove', 'Clear')]
        [string]$Operation,

        [Parameter()]
        [System.Security.Principal.SecurityIdentifier[]]$SecurityIdentifier,

        [Parameter()]
        [int]$AccessMask,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::None,

        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $sections = if ($RuleType -eq 'Audit') {
        [WindowsSecurityDescriptorSection]::Audit
    } else {
        [WindowsSecurityDescriptorSection]::Access
    }
    $getParameters = @{
        Target   = $Target
        Sections = $sections
    }
    $currentDescriptor = Get-WindowsServiceTargetSecurityDescriptor @getParameters
    $descriptor = $currentDescriptor
    $aceFlagMask = 0
    if (([int]$AuditFlags -band
        [int][System.Security.AccessControl.AuditFlags]::Success) -ne 0) {
        $aceFlagMask = $aceFlagMask -bor
            [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess
    }
    if (([int]$AuditFlags -band
        [int][System.Security.AccessControl.AuditFlags]::Failure) -ne 0) {
        $aceFlagMask = $aceFlagMask -bor
            [int][System.Security.AccessControl.AceFlags]::FailedAccess
    }

    if ($Operation -in @('Add', 'Set')) {
        foreach ($sid in $SecurityIdentifier) {
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = $RuleType
                Operation         = $Operation
                SecurityIdentifier = $sid
                AccessMask        = $AccessMask
                AccessControlType = $AccessControlType
                AceFlags          = [System.Security.AccessControl.AceFlags]$aceFlagMask
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
        }
    } elseif ($Operation -eq 'Remove') {
        $mutationParameters = @{
            SecurityDescriptor = $descriptor
            RuleType          = $RuleType
            Operation         = 'Remove'
            NativeAce         = $NativeAce
        }
        $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
    } elseif ($SecurityIdentifier.Count -eq 0) {
        $mutationParameters = @{
            SecurityDescriptor = $descriptor
            RuleType          = $RuleType
            Operation         = 'Clear'
        }
        $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
    } else {
        foreach ($sid in $SecurityIdentifier) {
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = $RuleType
                Operation         = 'Clear'
                SecurityIdentifier = $sid
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
        }
    }

    $setParameters = @{
        Target                    = $Target
        Sections                  = $sections
        SecurityDescriptor        = $descriptor
        CurrentSecurityDescriptor = $currentDescriptor
    }
    Set-WindowsServiceTargetSecurityDescriptor @setParameters
    $descriptor
}
