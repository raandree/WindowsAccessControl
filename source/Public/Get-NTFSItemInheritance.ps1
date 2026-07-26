function Get-NTFSItemInheritance {
    <#
    .SYNOPSIS
        Gets NTFS inheritance state for files and directories.

    .DESCRIPTION
        Reports whether access or audit rule inheritance is enabled, whether
        each selected ACL is protected, and whether its ACE order is canonical.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both. Reading audit
        inheritance can require SeSecurityPrivilege.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Get-NTFSItemInheritance -LiteralPath C:\Data -Section Access

        Reports the DACL inheritance and canonical-order state for C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.Inheritance
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
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        )
    )

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
            $descriptorSections = switch ($Section) {
                'Access' { [System.Security.AccessControl.AccessControlSections]::Access }
                'Audit' { [System.Security.AccessControl.AccessControlSections]::Audit }
                'All' {
                    [System.Security.AccessControl.AccessControlSections]::Access -bor
                        [System.Security.AccessControl.AccessControlSections]::Audit
                }
            }
            $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $descriptorSections
            ConvertTo-NTFSInheritanceObject -Security $security -Path $item.FullName -Section $Section
        }
    }
}
