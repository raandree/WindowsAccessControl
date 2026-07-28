. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Set-ADObjectSecurityDescriptor' `
    -RequiredParameters @('Server', 'DistinguishedName', 'AllowedBaseDistinguishedName', 'Sddl', 'Credential', 'TimeoutSeconds', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
