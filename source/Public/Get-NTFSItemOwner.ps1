function Get-NTFSItemOwner {
    <#
    .SYNOPSIS
        Gets the owner of files and directories.

    .DESCRIPTION
        Returns a structured owner object containing the filesystem path, the
        owner SID, and its translated account name when Windows can resolve it.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Get-NTFSItemOwner

        Gets owner information for each child item in C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.Owner
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
        [string[]]$LiteralPath
    )

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            ConvertTo-NTFSOwnerObject -Security $security -Path $item.FullName
        }
    }
}