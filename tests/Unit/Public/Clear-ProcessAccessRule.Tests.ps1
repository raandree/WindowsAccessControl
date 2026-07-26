. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Clear-ProcessAccessRule'
    RequiredParameters    = @('InputObject', 'Handle', 'Account', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
