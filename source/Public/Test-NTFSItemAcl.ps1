function Test-NTFSItemAcl {
    <#
    .SYNOPSIS
        Tests whether NTFS access control lists are canonical.

    .DESCRIPTION
        Tests the preferred Windows ACE order for the selected DACL, SACL, or
        both. Returns a Boolean by default or structured details with PassThru.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Section
        Selects whether the DACL, SACL, or both lists are tested.

    .PARAMETER PassThru
        Returns structured canonical-order results instead of a Boolean.

    .EXAMPLE
        Test-NTFSItemAcl -LiteralPath C:\Data -Section Access

        Returns true when the DACL on C:\Data is in canonical order.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        System.Boolean
        NTFSPermission.AclTest
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([bool], [pscustomobject])]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path = '.',

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $sections = [System.Security.AccessControl.AccessControlSections]::Access
            if ($Section -in @('Audit', 'All')) {
                $sections = $sections -bor [System.Security.AccessControl.AccessControlSections]::Audit
            }
            $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $sections
            $accessCanonical = if ($Section -in @('Access', 'All')) {
                $security.AreAccessRulesCanonical
            } else {
                $null
            }
            $auditCanonical = if ($Section -in @('Audit', 'All')) {
                $security.AreAuditRulesCanonical
            } else {
                $null
            }
            $isCanonical = ($accessCanonical -ne $false) -and ($auditCanonical -ne $false)

            if ($PassThru) {
                $result = [pscustomobject]@{
                    Path                 = $item.FullName
                    Section              = $Section
                    IsCanonical          = $isCanonical
                    AccessRulesCanonical = $accessCanonical
                    AuditRulesCanonical  = $auditCanonical
                }
                $result.PSObject.TypeNames.Insert(0, 'NTFSPermission.AclTest')
                $result
            } else {
                $isCanonical
            }
        }
    }
}