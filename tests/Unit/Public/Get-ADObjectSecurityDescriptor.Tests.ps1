. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-ADObjectSecurityDescriptor' `
    -RequiredParameters @('Server', 'DistinguishedName', 'Credential', 'TimeoutSeconds', 'ThrottleLimit') `
    -SupportsShouldProcess $false
