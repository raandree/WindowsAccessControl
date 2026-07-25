function Set-NTFSItemOwner {
    <#
    .SYNOPSIS
        Sets the owner of files and directories.

    .DESCRIPTION
        Sets a filesystem item's owner from an account name or SID. Setting an
        arbitrary owner can require SeRestorePrivilege; taking ownership can
        require SeTakeOwnershipPrivilege or suitable object permissions.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        The account name or SID that becomes the new item owner.

    .PARAMETER PassThru
        Returns the persisted owner information for each changed item.

    .EXAMPLE
        Get-Item -LiteralPath C:\Data | Set-NTFSItemOwner -Account 'BUILTIN\Administrators'

        Sets the owner of C:\Data to the local Administrators group.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        WindowsAccessControl.Owner
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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
    }

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            if ($PSCmdlet.ShouldProcess($item.FullName, "Set owner to $Account")) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $security.SetOwner($securityIdentifier)
                $persistenceParameters = @{
                    Item     = $item
                    Security = $security
                    Sections = 'Owner'
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters

                if ($PassThru) {
                    $updatedSecurity = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                    ConvertTo-NTFSOwnerObject -Security $updatedSecurity -Path $item.FullName
                }
            }
        }
    }
}
