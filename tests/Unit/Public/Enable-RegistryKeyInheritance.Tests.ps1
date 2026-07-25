. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Enable-RegistryKeyInheritance'
	RequiredParameters    = @('Path', 'Section', 'RemoveExplicitRules', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
