function Get-WindowsTaskSchedulerAclRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter()]
        [object[]]$Account,

        [Parameter()]
        [switch]$ExcludeInherited,

        [Parameter()]
        [switch]$ExcludeExplicit,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    if ($ExcludeInherited -and $ExcludeExplicit) {
        throw 'ExcludeInherited and ExcludeExplicit cannot be used together.'
    }
    $accountSids = @(
        foreach ($accountValue in $Account) {
            (Resolve-WindowsIdentityReference -Identity $accountValue).Value
        }
    )
    $descriptorBytes = Get-WindowsTaskSchedulerSecurityDescriptor -Target $Target
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $descriptorBytes,
        0
    )
    if (-not $descriptor.DiscretionaryAcl) {
        return
    }

    foreach ($ace in $descriptor.DiscretionaryAcl) {
        $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
        if (-not $qualifiedAce) {
            continue
        }
        $isInherited = ([int]$ace.AceFlags -band
            [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
        if (($ExcludeInherited -and $isInherited) -or
            ($ExcludeExplicit -and -not $isInherited)) {
            continue
        }
        if ($accountSids.Count -gt 0 -and
            $qualifiedAce.SecurityIdentifier.Value -notin $accountSids) {
            continue
        }
        ConvertTo-WindowsTaskSchedulerAccessRuleObject `
            -Ace $ace `
            -Target $Target `
            -TypeName $TypeName
    }
}
