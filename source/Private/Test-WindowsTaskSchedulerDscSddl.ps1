function Test-WindowsTaskSchedulerDscSddl {
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

    # The Task Scheduler service canonicalizes ACE order after a write, so exact
    # SDDL equality would report drift on every consistency run.
    Test-WindowsTaskSchedulerDaclEquivalent `
        -Left ([Security.AccessControl.RawSecurityDescriptor]::new($CurrentSddl)) `
        -Right ([Security.AccessControl.RawSecurityDescriptor]::new($DesiredSddl))
}
