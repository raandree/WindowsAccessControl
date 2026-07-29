function Get-WindowsAclRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,

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
    $sections = if ($RuleType -eq 'Audit') {
        [WindowsSecurityDescriptorSection]::Audit
    } else {
        [WindowsSecurityDescriptorSection]::Access
    }
    if ($Target.ObjectType -eq 'Process') {
        $getDescriptorParameters = @{
            Target   = $Target
            Sections = $sections
        }
        $descriptorBytes = Get-WindowsProcessTargetSecurityDescriptor @getDescriptorParameters
    } elseif ($Target.ObjectType -in @('Service', 'ServiceControlManager')) {
        $getDescriptorParameters = @{
            Target   = $Target
            Sections = $sections
        }
        $descriptorBytes = Get-WindowsServiceTargetSecurityDescriptor @getDescriptorParameters
    } else {
        $getDescriptorParameters = @{
            NativePath       = $Target.NativePath
            NativeObjectType = $Target.NativeObjectType
            Sections         = $sections
        }
        $descriptorBytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
    }
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $descriptorBytes,
        0
    )
    if ($RuleType -eq 'Audit') {
        $acl = $descriptor.SystemAcl
    } else {
        $acl = $descriptor.DiscretionaryAcl
    }
    if (-not $acl) {
        return
    }
    $accountSids = @(
        foreach ($accountValue in $Account) {
            (Resolve-WindowsIdentityReference -Identity $accountValue).Value
        }
    )
    $inheritanceSources = [string[]]@()
    if ($Target.ObjectType -eq 'RegistryKey' -and
        $RuleType -eq 'Access' -and
        -not $ExcludeInherited) {
        $inheritanceParameters = @{
            Target             = $Target
            SecurityDescriptor = $descriptorBytes
        }
        try {
            $inheritanceSources = Get-WindowsRegistryKeyInheritanceSource @inheritanceParameters
            if ($inheritanceSources.Count -notin @(0, $acl.Count)) {
                throw "Windows returned $($inheritanceSources.Count) inheritance sources for $($acl.Count) access-control entries."
            }
        } catch {
            # An ancestor key can be unreadable or change between the descriptor
            # read and the ancestor walk. Report the rules without provenance
            # rather than discarding a successful descriptor read.
            $inheritanceSources = [string[]]@()
            $errorParameters = @{
                Message      = "Cannot resolve inheritance sources for '$($Target.Path)': $($_.Exception.Message) Access rules are reported without an inheritance source."
                Category     = [System.Management.Automation.ErrorCategory]::ReadError
                TargetObject = $Target.Path
            }
            Write-Error @errorParameters
        }
    }

    for ($index = 0; $index -lt $acl.Count; $index++) {
        $ace = $acl[$index]
        $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
        if (-not $qualifiedAce) {
            continue
        }
        $isAuditAce = $qualifiedAce.AceQualifier -eq (
            [System.Security.AccessControl.AceQualifier]::SystemAudit
        )
        if (($RuleType -eq 'Audit') -ne $isAuditAce) {
            continue
        }
        $isInherited = ([int]$ace.AceFlags -band (
            [int][System.Security.AccessControl.AceFlags]::Inherited
        )) -ne 0
        if ($ExcludeInherited -and $isInherited) {
            continue
        }
        if ($ExcludeExplicit -and -not $isInherited) {
            continue
        }
        if ($accountSids.Count -gt 0 -and
            $qualifiedAce.SecurityIdentifier.Value -notin $accountSids) {
            continue
        }
        $conversionParameters = @{
            Ace      = $ace
            Target   = $Target
            RuleType = $RuleType
            TypeName = $TypeName
            InheritedFrom = if ($isInherited -and $index -lt $inheritanceSources.Count) {
                $inheritanceSources[$index]
            } else {
                $null
            }
            RightsType = switch ($Target.ObjectType) {
                Service { [WindowsServiceRights] }
                ServiceControlManager { [WindowsServiceControlManagerRights] }
                Process { [WindowsProcessRights] }
                SmbShare { [WindowsSmbShareRights] }
                default { [System.Security.AccessControl.RegistryRights] }
            }
            SupportsInheritance = $Target.ObjectType -eq 'RegistryKey'
        }
        ConvertTo-WindowsAclRuleObject @conversionParameters
    }
}
