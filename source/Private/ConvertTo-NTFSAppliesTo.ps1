function ConvertTo-NTFSAppliesTo {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags
    )

    $key = '{0}:{1}' -f [int]$InheritanceFlags, [int]$PropagationFlags
    $appliesTo = @{
        '0:0' = 'ThisFolderOnly'
        '3:0' = 'ThisFolderSubfoldersAndFiles'
        '1:0' = 'ThisFolderAndSubfolders'
        '2:0' = 'ThisFolderAndFiles'
        '3:2' = 'SubfoldersAndFilesOnly'
        '1:2' = 'SubfoldersOnly'
        '2:2' = 'FilesOnly'
        '3:1' = 'ThisFolderSubfoldersAndFilesOneLevel'
        '1:1' = 'ThisFolderAndSubfoldersOneLevel'
        '2:1' = 'ThisFolderAndFilesOneLevel'
        '3:3' = 'SubfoldersAndFilesOnlyOneLevel'
        '1:3' = 'SubfoldersOnlyOneLevel'
        '2:3' = 'FilesOnlyOneLevel'
    }

    if ($appliesTo.ContainsKey($key)) {
        $appliesTo[$key]
    } else {
        'Custom'
    }
}