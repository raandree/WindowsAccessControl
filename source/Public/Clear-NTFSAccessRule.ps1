function Clear-NTFSAccessRule {
    <#
    .SYNOPSIS
        Clears explicit NTFS access rules from files or directories.

    .DESCRIPTION
        Removes every explicitly assigned access rule while preserving the
        inherited access rules and the current inheritance protection state.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER PassThru
        Returns each explicit access rule that the command removed.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Clear-NTFSAccessRule -Confirm:$false

        Clears explicitly assigned access rules from every child item.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        NTFSPermission.AccessRule
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
            if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove every explicit access rule')) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $rules = @($security.GetAccessRules(
                    $true,
                    $false,
                    [System.Security.Principal.SecurityIdentifier]
                ))
                foreach ($rule in $rules) {
                    $security.RemoveAccessRuleSpecific($rule)
                }
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security

                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAccessRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}