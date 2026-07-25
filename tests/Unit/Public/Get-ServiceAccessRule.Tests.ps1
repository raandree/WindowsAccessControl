. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Get-ServiceAccessRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'ExcludeInherited', 'ExcludeExplicit')
    SupportsShouldProcess = $false
}
Register-ServiceCommandContract @contractParameters
