. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Remove-ServiceAccessRule'
    RequiredParameters    = @('InputObject', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
