function Get-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets portable NTFS security descriptors.

    .DESCRIPTION
        Returns selected security descriptor sections as SDDL together with
        structured metadata and the native FileSecurity or DirectorySecurity object.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Sections
        Selects owner, primary group, DACL, SACL, or any combination to return.
        Reading the Audit section can require SeSecurityPrivilege.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Get-NTFSItemSecurityDescriptor -Sections Access

        Gets a portable DACL descriptor for each child item in C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        NTFSPermission.SecurityDescriptor
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
        )
    )

    process {
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