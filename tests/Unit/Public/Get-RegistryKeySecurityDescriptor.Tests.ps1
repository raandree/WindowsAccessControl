. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Get-RegistryKeySecurityDescriptor'
	RequiredParameters    = @('Path', 'Sections', 'RegistryView')
	SupportsShouldProcess = $false
}
Register-RegistryKeyCommandContract @contractParameters
