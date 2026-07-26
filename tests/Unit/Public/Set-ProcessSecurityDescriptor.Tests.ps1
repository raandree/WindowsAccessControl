. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Set-ProcessSecurityDescriptor'
    RequiredParameters    = @('InputObject', 'Handle', 'Sddl', 'Sections', 'PassThru')
    SupportsShouldProcess = $true
}
Register-ProcessCommandContract @contractParameters
