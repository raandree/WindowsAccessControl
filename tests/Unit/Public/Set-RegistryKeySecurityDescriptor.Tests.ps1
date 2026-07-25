. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Set-RegistryKeySecurityDescriptor'
	RequiredParameters    = @('Path', 'Sddl', 'Sections', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
