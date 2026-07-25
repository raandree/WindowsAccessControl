. "$PSScriptRoot\RegistryKeyCommandContract.ps1"
$contractParameters = @{
	Name                  = 'Add-RegistryKeyAccessRule'
	RequiredParameters    = @('Path', 'Account', 'AccessRights', 'AccessControlType', 'AppliesTo', 'RegistryView', 'PassThru')
	SupportsShouldProcess = $true
}
Register-RegistryKeyCommandContract @contractParameters
