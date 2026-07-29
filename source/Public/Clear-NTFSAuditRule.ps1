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

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor with the Audit section loaded. When
        supplied, the explicit rules are cleared on the descriptor in memory and
        the descriptor is returned; nothing is written until
        Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER PassThru
        Returns each explicit audit rule that the command removed.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Clear-NTFSAuditRule -LiteralPath C:\Data -Confirm:$false

        Clears explicitly assigned audit rules from C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.AuditRule
        WindowsAccessControl.SecurityDescriptor
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

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.SecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $security = Assert-NTFSDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Audit
            $explicitRules = @($security.GetAuditRules(
                $true,
                $false,
                [System.Security.Principal.SecurityIdentifier]
            ))
            foreach ($explicitRule in $explicitRules) {
                $security.RemoveAuditRuleSpecific($explicitRule)
            }
            Update-NTFSSecurityDescriptorObject -Descriptor $SecurityDescriptor
            $SecurityDescriptor
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove every explicit audit rule')) {
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections Audit
                $rules = @($security.GetAuditRules(
                    $true,
                    $false,
                    [System.Security.Principal.SecurityIdentifier]
                ))
                foreach ($rule in $rules) {
                    $security.RemoveAuditRuleSpecific($rule)
                }
                $persistenceParameters = @{
                    Item     = $item
                    Security = $security
                    Sections = 'Audit'
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}
