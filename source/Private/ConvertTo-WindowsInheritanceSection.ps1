function ConvertTo-WindowsInheritanceSection {
    [CmdletBinding()]
    [OutputType([WindowsSecurityDescriptorSection])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section
    )

    switch ($Section) {
        'Access' { [WindowsSecurityDescriptorSection]::Access }
        'Audit' { [WindowsSecurityDescriptorSection]::Audit }
        'All' {
            [WindowsSecurityDescriptorSection]::Access -bor
                [WindowsSecurityDescriptorSection]::Audit
        }
    }
}
