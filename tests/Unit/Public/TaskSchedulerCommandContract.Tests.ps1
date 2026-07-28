. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-TaskFolderSecurityDescriptor' `
    -RequiredParameters @('Path', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Register-EnterpriseCommandContract `
    -Name 'Set-TaskFolderSecurityDescriptor' `
    -RequiredParameters @('Path', 'AllowedRootPath', 'Sddl', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Register-EnterpriseCommandContract `
    -Name 'Get-ScheduledTaskSecurityDescriptor' `
    -RequiredParameters @('TaskPath', 'TaskName', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Register-EnterpriseCommandContract `
    -Name 'Set-ScheduledTaskSecurityDescriptor' `
    -RequiredParameters @('TaskPath', 'TaskName', 'AllowedRootPath', 'Sddl', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true