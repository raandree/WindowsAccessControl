function ConvertTo-WindowsTaskSchedulerAccessRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.GenericAce]$Ace,

        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $qualifiedAce = $Ace -as [System.Security.AccessControl.QualifiedAce]
    $knownAce = $Ace -as [System.Security.AccessControl.KnownAce]
    if (-not $qualifiedAce -or -not $knownAce -or
        $qualifiedAce.AceQualifier -notin @(
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            [System.Security.AccessControl.AceQualifier]::AccessDenied
        )) {
        return
    }
    $account = $null
    $isOrphaned = $false
    try {
        $account = $qualifiedAce.SecurityIdentifier.Translate(
            [System.Security.Principal.NTAccount]
        ).Value
    }
    catch [System.Security.Principal.IdentityNotMappedException] {
        $isOrphaned = $true
    }

    $inheritanceMask = [int]$Ace.AceFlags -band (
        [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor
        [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
        [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
    )
    $appliesToByMask = @{
        0  = 'ThisFolderOnly'
        3  = 'ThisFolderSubfoldersAndTasks'
        2  = 'ThisFolderAndSubfolders'
        1  = 'ThisFolderAndTasks'
        11 = 'SubfoldersAndTasksOnly'
        10 = 'SubfoldersOnly'
        9  = 'TasksOnly'
    }
    $appliesTo = if ($appliesToByMask.ContainsKey($inheritanceMask)) {
        $appliesToByMask[$inheritanceMask]
    }
    else {
        'Custom'
    }

    $rightsType = if ($Target.ObjectType -eq 'ScheduledTask') {
        [WindowsScheduledTaskRights]
    }
    else {
        [WindowsTaskFolderRights]
    }
    $accessMask = [uint64]([int64]$knownAce.AccessMask -band 0xFFFFFFFFL)

    $result = [pscustomobject]@{
        ObjectType        = $Target.ObjectType
        Path              = $Target.Path
        TaskPath          = $Target.TaskPath
        TaskName          = $Target.TaskName
        CanonicalTarget   = $Target.CanonicalTarget
        RuleType          = 'Access'
        Account           = $account
        SID               = $qualifiedAce.SecurityIdentifier.Value
        IsOrphaned        = $isOrphaned
        AccessMask        = $accessMask
        AccessRights      = [System.Enum]::ToObject($rightsType, $knownAce.AccessMask)
        AccessRightsDisplay = ConvertTo-WindowsAccessRightsDisplay `
            -AccessMask $accessMask `
            -RightsType $rightsType
        AccessControlType = if ($qualifiedAce.AceQualifier -eq
            [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            [System.Security.AccessControl.AccessControlType]::Deny
        }
        else {
            [System.Security.AccessControl.AccessControlType]::Allow
        }
        AppliesTo         = $appliesTo
        IsInherited       = ([int]$Ace.AceFlags -band
            [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
        AceFlags          = $Ace.AceFlags
        IdentityReference = $qualifiedAce.SecurityIdentifier
        NativeAce         = $Ace
    }
    $result.PSObject.TypeNames.Insert(0, $TypeName)
    $result.PSObject.TypeNames.Add('WindowsAccessControl.Rule')
    $result
}
