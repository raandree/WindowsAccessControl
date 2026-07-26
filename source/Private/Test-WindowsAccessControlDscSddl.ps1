function Test-WindowsAccessControlDscSddl {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CurrentSddl,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DesiredSddl,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    $currentDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $CurrentSddl
    )
    $desiredDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $DesiredSddl
    )
    $currentComparable = Get-WindowsAccessControlDscComparableSddl `
        -SecurityDescriptor $currentDescriptor `
        -Sections $Sections
    $desiredComparable = Get-WindowsAccessControlDscComparableSddl `
        -SecurityDescriptor $desiredDescriptor `
        -Sections $Sections
    $currentComparable -ceq $desiredComparable
}
