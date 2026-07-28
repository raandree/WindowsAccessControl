. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Set-SmbShareSecurityDescriptor' `
    -RequiredParameters @('Name', 'Sddl', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
