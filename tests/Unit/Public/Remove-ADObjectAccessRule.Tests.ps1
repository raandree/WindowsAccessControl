. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Remove-ADObjectAccessRule' `
    -RequiredParameters @('InputObject', 'AllowedBaseDistinguishedName', 'Credential', 'TimeoutSeconds', 'PassThru') `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false
