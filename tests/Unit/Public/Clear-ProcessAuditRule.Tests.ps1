. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Clear-ProcessAuditRule'
    RequiredParameters    = @('InputObject', 'Handle', 'Account', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
