. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Get-ServiceAuditRule'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Account', 'ExcludeInherited', 'ExcludeExplicit')
    SupportsShouldProcess = $false
}
Register-ServiceCommandContract @contractParameters
