. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Get-SmbShareSecurityDescriptor' `
    -RequiredParameters @('Name', 'ThrottleLimit') `
    -SupportsShouldProcess $false
