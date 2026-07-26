. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Remove-ProcessAuditRule'
    RequiredParameters    = @('InputObject', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
