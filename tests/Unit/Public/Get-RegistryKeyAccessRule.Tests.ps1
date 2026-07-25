. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Get-RegistryKeyAccessRule'
	RequiredParameters    = @('Path', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'RegistryView')
	SupportsShouldProcess = $false
}
Register-RegistryKeyCommandContract @contractParameters
