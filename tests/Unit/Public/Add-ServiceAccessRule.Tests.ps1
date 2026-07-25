. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Add-ServiceAccessRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'ServiceRights', 'ControlManagerRights', 'AccessControlType', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
