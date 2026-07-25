. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Add-RegistryKeyAuditRule'
	RequiredParameters    = @('Path', 'Account', 'AccessRights', 'AuditFlags', 'AppliesTo', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
