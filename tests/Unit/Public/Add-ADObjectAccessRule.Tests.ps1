. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Add-ADObjectAccessRule' `
    -RequiredParameters @('Server', 'DistinguishedName', 'AllowedBaseDistinguishedName', 'Credential', 'Account', 'AccessRights', 'AccessControlType', 'InheritanceType', 'ObjectType', 'InheritedObjectType', 'TimeoutSeconds', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
