function Clear-NTFSAuditRule {
    <#
    .SYNOPSIS
        Clears explicit NTFS audit rules from files or directories.

    .DESCRIPTION
        Removes every explicitly assigned audit rule while preserving inherited
        SACL entries and the current audit inheritance protection state.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem provider.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied.

    .PARAMETER PassThru
        Returns each explicit audit rule that the command removed.

    .EXAMPLE
        Clear-NTFSAuditRule -LiteralPath C:\Data -Confirm:$false

        Clears explicitly assigned audit rules from C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        WindowsAccessControl.AuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

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
            if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove every explicit audit rule')) {
                $security = Get-Acl -LiteralPath $item.FullName -Audit -ErrorAction Stop
                $rules = @($security.GetAuditRules(
                    $true,
                    $false,
                    [System.Security.Principal.SecurityIdentifier]
                ))
                foreach ($rule in $rules) {
                    $security.RemoveAuditRuleSpecific($rule)
                }
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security
                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}