. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Get-ServiceSecurityDescriptor'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Sections')
    SupportsShouldProcess = $false
}
Register-ServiceCommandContract @contractParameters
