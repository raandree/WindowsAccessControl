. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-SmbShareAccessRule' `
    -RequiredParameters @('Name', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'ThrottleLimit') `
    -SupportsShouldProcess $false
