. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Get-ProcessSecurityDescriptor'
    RequiredParameters    = @('InputObject', 'Handle', 'Sections')
    SupportsShouldProcess = $false
}
Register-ProcessCommandContract @contractParameters
