. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-ADObjectSchemaDefaultAccessRule' `
    -RequiredParameters @('Server', 'ObjectClass', 'Credential', 'TimeoutSeconds') `
    -SupportsShouldProcess $false `
    -SupportsTargetArrays $false
