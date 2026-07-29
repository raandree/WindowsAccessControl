function Get-NTFSDescriptorAppliesTo {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [psobject]$SecurityDescriptor,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppliesTo
    )

    if (-not [string]::IsNullOrEmpty($AppliesTo)) {
        return $AppliesTo
    }
    if ($SecurityDescriptor.ItemType -eq 'Directory') {
        'ThisFolderSubfoldersAndFiles'
    } else {
        'ThisFolderOnly'
    }
}
