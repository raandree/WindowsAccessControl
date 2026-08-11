. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-ADObjectAccessRule' `
    -RequiredParameters @('Server', 'DistinguishedName', 'Credential', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'ExcludeSchemaDefault', 'TimeoutSeconds', 'ThrottleLimit') `
    -SupportsShouldProcess $false
