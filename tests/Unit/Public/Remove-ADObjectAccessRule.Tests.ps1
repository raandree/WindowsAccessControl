. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Remove-ADObjectAccessRule' `
    -RequiredParameters @('InputObject', 'Server', 'DistinguishedName', 'AllowedBaseDistinguishedName', 'Credential', 'Account', 'AccessRights', 'AccessControlType', 'InheritanceType', 'ObjectType', 'InheritedObjectType', 'RemovalMode', 'TimeoutSeconds', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true
