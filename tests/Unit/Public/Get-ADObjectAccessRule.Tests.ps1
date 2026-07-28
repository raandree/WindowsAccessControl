. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-ADObjectAccessRule' `
    -RequiredParameters @('Server', 'DistinguishedName', 'Credential', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'TimeoutSeconds', 'ThrottleLimit') `
    -SupportsShouldProcess $false
