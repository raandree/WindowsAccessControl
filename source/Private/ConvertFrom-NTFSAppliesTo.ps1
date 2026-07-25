function ConvertFrom-NTFSAppliesTo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndFiles',
            'ThisFolderAndSubfolders',
            'ThisFolderAndFiles',
            'SubfoldersAndFilesOnly',
            'SubfoldersOnly',
            'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel',
            'ThisFolderAndSubfoldersOneLevel',
            'ThisFolderAndFilesOneLevel'
        )]
        [string]$AppliesTo
    )

    $containerInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $objectInherit = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $oneLevel = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit

    switch ($AppliesTo) {
        'ThisFolderOnly' {
            @{ InheritanceFlags = 'None'; PropagationFlags = 'None' }
        }
        'ThisFolderSubfoldersAndFiles' {
            @{ InheritanceFlags = $containerInherit -bor $objectInherit; PropagationFlags = 'None' }
        }
        'ThisFolderAndSubfolders' {
            @{ InheritanceFlags = $containerInherit; PropagationFlags = 'None' }
        }
        'ThisFolderAndFiles' {
            @{ InheritanceFlags = $objectInherit; PropagationFlags = 'None' }
        }
        'SubfoldersAndFilesOnly' {
            @{ InheritanceFlags = $containerInherit -bor $objectInherit; PropagationFlags = $inheritOnly }
        }
        'SubfoldersOnly' {
            @{ InheritanceFlags = $containerInherit; PropagationFlags = $inheritOnly }
        }
        'FilesOnly' {
            @{ InheritanceFlags = $objectInherit; PropagationFlags = $inheritOnly }
        }
        'ThisFolderSubfoldersAndFilesOneLevel' {
            @{ InheritanceFlags = $containerInherit -bor $objectInherit; PropagationFlags = $oneLevel }
        }
        'ThisFolderAndSubfoldersOneLevel' {
            @{ InheritanceFlags = $containerInherit; PropagationFlags = $oneLevel }
        }
        'ThisFolderAndFilesOneLevel' {
            @{ InheritanceFlags = $objectInherit; PropagationFlags = $oneLevel }
        }
    }
}