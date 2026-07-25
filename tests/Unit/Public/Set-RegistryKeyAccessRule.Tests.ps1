. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Set-RegistryKeyAccessRule'
	RequiredParameters    = @('Path', 'Account', 'AccessRights', 'AccessControlType', 'AppliesTo', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
