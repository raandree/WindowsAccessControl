. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Clear-ADObjectAccessRule' `
    -RequiredParameters @('Server', 'DistinguishedName', 'AllowedBaseDistinguishedName', 'Credential', 'Account', 'TimeoutSeconds', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
