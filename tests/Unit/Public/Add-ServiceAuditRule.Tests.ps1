. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Add-ServiceAuditRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'ServiceRights', 'ControlManagerRights', 'AuditFlags', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
