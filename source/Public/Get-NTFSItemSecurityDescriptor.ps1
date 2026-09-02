function Get-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets portable NTFS security descriptors.

    .DESCRIPTION
        Returns selected security descriptor sections as SDDL together with
        structured metadata and the native FileSecurity or DirectorySecurity object.
        A junction, a symbolic link, or a volume mount point carries its own
        descriptor and is reported as itself, not as its destination.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Sections
        Selects owner, primary group, DACL, SACL, or any combination to return.
        Reading the Audit section can require SeSecurityPrivilege.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Get-NTFSItemSecurityDescriptor -Sections Access

        Gets a portable DACL descriptor for each child item in C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.SecurityDescriptor
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
        [System.Security.AccessControl.AccessControlSections]$Sections = (
            [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group -bor
            [System.Security.AccessControl.AccessControlSections]::Access
        ),

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
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
            $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $Sections
            ConvertTo-NTFSSecurityDescriptorObject -Item $item -Security $security -Sections $Sections
        }
    }
}
