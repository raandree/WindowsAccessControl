. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Clear-ServiceAuditRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
