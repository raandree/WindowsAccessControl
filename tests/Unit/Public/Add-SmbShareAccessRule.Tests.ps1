. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Add-SmbShareAccessRule' `
    -RequiredParameters @('Name', 'Account', 'AccessRights', 'AccessControlType', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
