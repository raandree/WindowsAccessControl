. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Disable-RegistryKeyInheritance'
	RequiredParameters    = @('Path', 'Section', 'PreserveInherited', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
