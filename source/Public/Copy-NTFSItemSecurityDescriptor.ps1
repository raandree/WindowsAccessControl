function Copy-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Copies selected NTFS security descriptor sections.

    .DESCRIPTION
        Copies only the requested owner, group, DACL, or SACL sections from one
        source item to one or more destination items. Other sections are preserved.

    .PARAMETER SourceLiteralPath
        The literal filesystem path whose selected descriptor sections are copied.

    .PARAMETER Path
        One or more destination paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more destination paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Sections
        Selects the descriptor sections copied to each destination item.

    .PARAMETER PassThru
        Returns each destination security descriptor after the copy completes.

    .EXAMPLE
        Get-ChildItem C:\Target | Copy-NTFSItemSecurityDescriptor -SourceLiteralPath C:\Template -Sections Access

        Copies the template DACL to each child item under C:\Target.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        NTFSPermission.SecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$SourceLiteralPath,

        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path,

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
        [switch]$PassThru
    )

    begin {
        $sourceItems = @(Resolve-NTFSPath -LiteralPath $SourceLiteralPath)
        if ($sourceItems.Count -ne 1) {
            throw 'SourceLiteralPath must resolve to exactly one filesystem item.'
        }
        $sourceSecurity = Get-NTFSSecurityDescriptorForItem -Item $sourceItems[0] -Sections $Sections
        $sourceSddl = $sourceSecurity.GetSecurityDescriptorSddlForm($Sections)
    }

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $action = "Copy $Sections security descriptor sections from $SourceLiteralPath"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $Sections
                $security.SetSecurityDescriptorSddlForm($sourceSddl, $Sections)
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security
                if ($PassThru) {
                    $updated = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $Sections
                    ConvertTo-NTFSSecurityDescriptorObject -Item $item -Security $updated -Sections $Sections
                }
            }
        }
    }
}