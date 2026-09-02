function Get-NTFSAccessRule {
    <#
    .SYNOPSIS
        Gets NTFS access rules for files and directories.

    .DESCRIPTION
        Returns structured access-rule objects for each filesystem path. Rules
        can be filtered by account and by whether they are explicit or
        inherited. InheritedFrom identifies the original ancestor reported by
        the Windows inheritance-source API. It is empty for explicit rules or
        when Windows cannot identify an inherited ancestor. The output can be
        piped to other module commands. A junction, a symbolic link, or a volume
        mount point carries its own descriptor and is reported as itself, not as
        its destination.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        Limits output to one or more account names or SID strings.

    .PARAMETER ExcludeInherited
        Omits access rules inherited from a parent directory.

    .PARAMETER ExcludeExplicit
        Omits access rules that are explicitly assigned to the item.

    .PARAMETER Orphaned
        Returns only rules whose security identifier cannot be translated to
        an account name.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Get-NTFSAccessRule -ExcludeInherited

        Gets explicit access rules for every child item in C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.AccessRule
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
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

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
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -ConfirmationImpact None
            return
        }
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $rules = @($security.GetAccessRules(
                $true,
                -not $ExcludeInherited,
                [System.Security.Principal.SecurityIdentifier]
            ))
            $inheritanceSources = @()
            if (-not $ExcludeInherited -and $rules.Count -gt 0) {
                $inheritanceSources = @(
                    [WindowsAccessControl.NativeMethods]::GetFileSystemAccessRuleInheritanceSources(
                        $item.FullName,
                        $item -is [System.IO.DirectoryInfo],
                        $security.GetSecurityDescriptorBinaryForm()
                    )
                )
                if ($rules.Count -ne $inheritanceSources.Count) {
                    throw "Windows returned $($inheritanceSources.Count) inheritance sources for $($rules.Count) access rules on '$($item.FullName)'."
                }
            }

            for ($ruleIndex = 0; $ruleIndex -lt $rules.Count; $ruleIndex++) {
                $rule = $rules[$ruleIndex]
                if ($ExcludeExplicit -and -not $rule.IsInherited) {
                    continue
                }
                $conversionParameters = @{
                    Rule          = $rule
                    Path          = $item.FullName
                    InheritedFrom = if ($ExcludeInherited) {
                        $null
                    } else {
                        $inheritanceSources[$ruleIndex].AncestorName
                    }
                }
                $result = ConvertTo-NTFSAccessRuleObject @conversionParameters
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
