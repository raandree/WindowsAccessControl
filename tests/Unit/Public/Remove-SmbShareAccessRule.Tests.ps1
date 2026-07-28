. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Remove-SmbShareAccessRule' `
    -RequiredParameters @('InputObject', 'PassThru') `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false
