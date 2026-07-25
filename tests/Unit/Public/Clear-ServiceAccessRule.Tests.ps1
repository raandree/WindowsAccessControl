. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Clear-ServiceAccessRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
