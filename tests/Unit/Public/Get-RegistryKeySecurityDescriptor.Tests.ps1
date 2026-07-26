. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Get-RegistryKeySecurityDescriptor'
	RequiredParameters    = @('Path', 'Sections', 'RegistryView', 'ThrottleLimit')
	SupportsShouldProcess = $false
}
Register-RegistryKeyCommandContract @contractParameters
