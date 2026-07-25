. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Set-ServiceAuditRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'ServiceRights', 'ControlManagerRights', 'AuditFlags', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
