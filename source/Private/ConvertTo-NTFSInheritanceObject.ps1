function ConvertTo-NTFSInheritanceObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.ObjectSecurity]$Security,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section
    )

    $accessEnabled = $null
    $accessProtected = $null
    $accessCanonical = $null
    $auditEnabled = $null
    $auditProtected = $null
    $auditCanonical = $null

    if ($Section -in @('Access', 'All')) {
        $accessProtected = $Security.AreAccessRulesProtected
        $accessEnabled = -not $accessProtected
        $accessCanonical = $Security.AreAccessRulesCanonical
    }
    if ($Section -in @('Audit', 'All')) {
        $auditProtected = $Security.AreAuditRulesProtected
        $auditEnabled = -not $auditProtected
        $auditCanonical = $Security.AreAuditRulesCanonical
    }

    $result = [pscustomobject]@{
        Path                     = $Path
        Section                  = $Section
        AccessInheritanceEnabled = $accessEnabled
        AccessRulesProtected     = $accessProtected
        AccessRulesCanonical     = $accessCanonical
        AuditInheritanceEnabled  = $auditEnabled
        AuditRulesProtected      = $auditProtected
        AuditRulesCanonical      = $auditCanonical
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.Inheritance')
    $result
}