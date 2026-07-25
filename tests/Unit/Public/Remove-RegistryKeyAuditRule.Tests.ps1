. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Remove-RegistryKeyAuditRule'
	RequiredParameters    = @('InputObject', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
