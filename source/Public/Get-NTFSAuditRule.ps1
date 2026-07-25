function Get-NTFSAuditRule {
    <#
    .SYNOPSIS
        Gets NTFS audit rules for files and directories.

    .DESCRIPTION
        Returns structured SACL audit-rule objects filtered by account and by
        explicit or inherited origin. Reading SACLs requires SeSecurityPrivilege.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        Limits output to one or more account names or SID strings.

    .PARAMETER ExcludeInherited
        Omits audit rules inherited from a parent directory.

    .PARAMETER ExcludeExplicit
        Omits audit rules that are explicitly assigned to the item.

    .PARAMETER Orphaned
        Returns only rules whose SID cannot be translated to an account name.

    .EXAMPLE
        Get-NTFSAuditRule -LiteralPath C:\Data -ExcludeInherited

        Gets the explicit audit rules assigned to C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.AuditRule
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path = '.',

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Account,

        [Parameter()]
        [switch]$ExcludeInherited,

        [Parameter()]
        [switch]$ExcludeExplicit,

        [Parameter()]
        [switch]$Orphaned
    )

    begin {
        if ($ExcludeInherited -and $ExcludeExplicit) {
            throw 'ExcludeInherited and ExcludeExplicit cannot be used together.'
        }
        $accountSids = @(
            foreach ($accountName in $Account) {
                (Resolve-WindowsIdentityReference -Identity $accountName).Value
            }
        )
    }

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections Audit
            $rules = $security.GetAuditRules(
                -not $ExcludeExplicit,
                -not $ExcludeInherited,
                [System.Security.Principal.SecurityIdentifier]
            )
            foreach ($rule in $rules) {
                $result = ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                if ($accountSids.Count -gt 0 -and $result.SID -notin $accountSids) {
                    continue
                }
                if ($Orphaned -and -not $result.IsOrphaned) {
                    continue
                }
                $result
            }
        }
    }
}
