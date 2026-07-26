function Backup-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Backs up NTFS security descriptors to JSON.

    .DESCRIPTION
        Writes a versioned, non-executable JSON document containing each item
        path, item type, selected section bitmask, and SDDL descriptor.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER DestinationPath
        The literal JSON file path written after all pipeline items are collected.

    .PARAMETER Sections
        Selects the descriptor sections stored in each backup record.

    .PARAMETER Force
        Allows an existing backup file to be overwritten. Without Force, the
        command refuses to replace an existing file.

    .PARAMETER PassThru
        Returns each backup record after the JSON document is written.

    .EXAMPLE
        Get-ChildItem C:\Data | Backup-NTFSItemSecurityDescriptor -DestinationPath C:\Backup\permissions.json

        Backs up owner, group, and DACL sections for each child item.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        WindowsAccessControl.SecurityDescriptorBackupRecord
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationPath,

        [Parameter()]
        [System.Security.AccessControl.AccessControlSections]$Sections = (
            [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group -bor
            [System.Security.AccessControl.AccessControlSections]::Access
        ),

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $descriptors = [System.Collections.Generic.List[object]]::new()
    }

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $Sections
            $descriptor = ConvertTo-NTFSSecurityDescriptorObject `
                -Item $item `
                -Security $security `
                -Sections $Sections
            $descriptors.Add($descriptor)
        }
    }

    end {
        $resolvedDestination = [System.IO.Path]::GetFullPath($DestinationPath)
        $parentPath = [System.IO.Path]::GetDirectoryName($resolvedDestination)
        if (-not [System.IO.Directory]::Exists($parentPath)) {
            throw "Backup destination directory does not exist: $parentPath"
        }
        if ([System.IO.Directory]::Exists($resolvedDestination)) {
            throw "Backup destination is a directory: $resolvedDestination"
        }
        $destinationExists = [System.IO.File]::Exists($resolvedDestination)
        if ($destinationExists -and -not $Force) {
            throw "Backup destination already exists: $resolvedDestination. Use Force to overwrite it."
        }
        $action = if ($destinationExists) {
            "Overwrite with $($descriptors.Count) security descriptor records"
        } else {
            "Write $($descriptors.Count) security descriptor records"
        }
        if ($PSCmdlet.ShouldProcess($resolvedDestination, $action)) {
            $backupParameters = @{
                InputObject     = $descriptors.ToArray()
                DestinationPath = $resolvedDestination
                Force           = $Force
                PassThru        = $PassThru
                Confirm         = $false
            }
            Backup-WindowsSecurityDescriptor @backupParameters
        }
    }
}
