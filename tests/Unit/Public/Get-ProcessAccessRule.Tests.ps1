. "$PSScriptRoot\ProcessCommandContract.ps1"
$contractParameters = @{
    Name                  = 'Get-ProcessAccessRule'
    RequiredParameters    = @('InputObject', 'Handle', 'Account', 'ExcludeInherited', 'ExcludeExplicit')
    SupportsShouldProcess = $false
}
Register-ProcessCommandContract @contractParameters
