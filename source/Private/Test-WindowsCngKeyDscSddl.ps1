function Test-WindowsCngKeyDscSddl {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CurrentSddl,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DesiredSddl
    )

    # The provider stores a candidate ACE with the matching generic bit added,
    # so a requested 0x00120089 reads back as 0x80120089 and exact SDDL equality
    # would report drift on every consistency run. Order is ignored for the same
    # reason the write boundary treats an allow-only reordering as already
    # converged: the provider decides the stored order.
    Test-WindowsCngKeyDaclEquivalent `
        -Left ([Security.AccessControl.RawSecurityDescriptor]::new($CurrentSddl)) `
        -Right ([Security.AccessControl.RawSecurityDescriptor]::new($DesiredSddl))
}
