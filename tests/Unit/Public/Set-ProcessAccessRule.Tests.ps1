. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Set-ProcessAccessRule'
    RequiredParameters    = @('InputObject', 'Handle', 'Account', 'ProcessRights', 'AccessControlType', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
