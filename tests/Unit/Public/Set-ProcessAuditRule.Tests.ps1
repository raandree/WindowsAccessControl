. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Set-ProcessAuditRule'
    RequiredParameters    = @('InputObject', 'Handle', 'Account', 'ProcessRights', 'AuditFlags', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
