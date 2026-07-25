. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Remove-RegistryKeyAccessRule'
	RequiredParameters    = @('InputObject', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
