. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Clear-RegistryKeyAuditRule'
	RequiredParameters    = @('Path', 'Account', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
