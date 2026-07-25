. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Get-RegistryKeyInheritance'
	RequiredParameters    = @('Path', 'Section', 'RegistryView')
	SupportsShouldProcess = $false
}
Register-RegistryKeyCommandContract @contractParameters
