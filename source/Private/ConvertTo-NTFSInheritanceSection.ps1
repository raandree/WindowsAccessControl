function ConvertTo-NTFSInheritanceSection {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AccessControlSections])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section
    )

    switch ($Section) {
        'Access' { [System.Security.AccessControl.AccessControlSections]::Access }
        'Audit' { [System.Security.AccessControl.AccessControlSections]::Audit }
        'All' {
            [System.Security.AccessControl.AccessControlSections]::Access -bor
                [System.Security.AccessControl.AccessControlSections]::Audit
        }
    }
}
