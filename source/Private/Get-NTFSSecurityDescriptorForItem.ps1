function Get-NTFSSecurityDescriptorForItem {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemSecurity])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileSystemInfo]$Item,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlSections]$Sections
    )

    $getAclParameters = @{
        LiteralPath = $Item.FullName
        ErrorAction = 'Stop'
    }
    $readDescriptor = {
        param($parameters)

        Get-Acl @parameters
    }
    $auditSelected = ($Sections -band
        [System.Security.AccessControl.AccessControlSections]::Audit) -ne 0
    $accessSelected = ($Sections -band
        [System.Security.AccessControl.AccessControlSections]::Access) -ne 0

    if (-not $auditSelected) {
        return (& $readDescriptor $getAclParameters)
    }

    $auditParameters = $getAclParameters.Clone()
    $auditParameters.Audit = $true
    $privilegeParameters = @{
        Name         = 'SeSecurityPrivilege'
        ScriptBlock  = $readDescriptor
        ArgumentList = ,$auditParameters
    }
    $auditSecurity = Invoke-WithWindowsPrivilege @privilegeParameters

    if (-not $accessSelected) {
        return $auditSecurity
    }

    # GetNamedSecurityInfo clears INHERITED_ACE on every DACL ACE when the SACL
    # is requested, so a combined read reports inherited ACEs as explicit and
    # replays them as explicit. Take the DACL from a read that omits the SACL
    # and graft the audited SACL onto it. Grafting marks only the audit section
    # modified, so a later persist writes the SACL the caller already selected.
    $security = & $readDescriptor $getAclParameters
    $security.SetSecurityDescriptorBinaryForm(
        $auditSecurity.GetSecurityDescriptorBinaryForm(),
        [System.Security.AccessControl.AccessControlSections]::Audit
    )
    $security
}
