. "$PSScriptRoot\ServiceCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Set-ServiceSecurityDescriptor'
    RequiredParameters    = @('Name', 'ServiceControlManager', 'Sddl', 'Sections', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ServiceCommandContract @contractParameters
