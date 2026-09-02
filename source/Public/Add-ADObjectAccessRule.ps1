function Add-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Adds typed access rules to bounded Active Directory object DACLs.
    .DESCRIPTION
        Prevalidates identities and a disposable OU boundary, adds idempotent
        common or object-specific ACEs, and revalidates object GUID before LDAP write.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller. When it
        is omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to modify.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds every permitted mutation.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        Active Directory rights to add.
    .PARAMETER AccessControlType
        Adds an Allow rule by default or an explicit Deny rule.
    .PARAMETER InheritanceType
        Controls directory inheritance for the new ACE.
    .PARAMETER ObjectType
        Optionally scopes the ACE to an object, property, or extended-right
        GUID, or to the schema class, attribute, property set, validated write,
        or extended right name that identifies it.
    .PARAMETER InheritedObjectType
        Optionally scopes inherited application to an object-class GUID or to
        the schema class name that identifies it.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .PARAMETER PassThru
        Returns the stored explicit access rule after persistence.
    .EXAMPLE
        Add-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights ReadProperty -WhatIf

        Previews adding an explicit read-property ACE inside the allowed OU.
    .EXAMPLE
        Add-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights 'ReadProperty, WriteProperty' -Confirm:$false -PassThru

        Grants read and write property rights through an automatically located
        writable domain controller and returns the stored ACE.
    .EXAMPLE
        Add-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\Analysts', 'CONTOSO\Auditors' -AccessRights ReadProperty -Confirm:$false

        Adds the same read-property ACE for two groups with one LDAP write.
    .EXAMPLE
        Add-ADObjectAccessRule -DistinguishedName $ou -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights 'ReadProperty, WriteProperty' -ObjectType 'employeeID' -InheritanceType Descendents -InheritedObjectType 'user' -Confirm:$false

        Delegates read and write access to only the employeeID attribute on
        every descendant user object, without granting any other property.
    .EXAMPLE
        Add-ADObjectAccessRule -DistinguishedName $ou -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\HelpDesk' -AccessRights ExtendedRight -ObjectType 'Reset Password' -InheritanceType Descendents -InheritedObjectType 'user' -Confirm:$false

        Delegates the Reset Password extended right to the help desk group on
        every descendant user object, the same scope the Delegation of Control
        wizard grants.
    .EXAMPLE
        Add-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\Contractors' -AccessRights GenericAll -AccessControlType Deny -Confirm:$false

        Adds an explicit deny rule that blocks the contractors group from
        every right on the object. An inherited allow rule for the same group
        is not removed by this command, so review Get-ADObjectAccessRule
        before relying on the deny to be the deciding ACE.
    .EXAMPLE
        Get-ADObject -SearchBase $ou -Filter "objectClass -eq 'organizationalUnit'" |
            Select-Object -ExpandProperty DistinguishedName |
            Add-ADObjectAccessRule -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights ReadProperty -ThrottleLimit 4 -Confirm:$false

        Grants the same read-property ACE to every organizational unit under
        the allowed OU, processing up to four targets concurrently.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Path')]
        [object[]]$DistinguishedName,
        [Parameter(Mandatory)]
        [string]$AllowedBaseDistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter(Mandatory)]
        [WindowsAccessRightsTransformAttribute([WindowsActiveDirectoryRights])]
        $AccessRights,
        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
        [Parameter()]
        [WindowsActiveDirectoryInheritance]$InheritanceType =
            [WindowsActiveDirectoryInheritance]::None,
        [Parameter()]
        [AllowEmptyString()]
        [string]$ObjectType,
        [Parameter()]
        [AllowEmptyString()]
        [string]$InheritedObjectType,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $identities = @(
            foreach ($accountValue in $Account) {
                $sid = Resolve-WindowsIdentityReference -Identity $accountValue
                if ($seen.Add($sid.Value)) { $sid }
            }
        )
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Assert-WindowsADDistinguishedNameInput -DistinguishedName $DistinguishedName
            if (-not $pinnedServer) {
                $pinnedServer = Resolve-WindowsADServer -Server $Server
            }
            $PSBoundParameters['Server'] = $pinnedServer
            if (-not $objectTypes) {
                $objectTypes = Resolve-WindowsADObjectTypeGuid `
                    -ObjectType $ObjectType `
                    -InheritedObjectType $InheritedObjectType `
                    -Server $pinnedServer `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds
            }
            foreach ($typeParameter in 'ObjectType', 'InheritedObjectType') {
                if ($PSBoundParameters.ContainsKey($typeParameter)) {
                    $PSBoundParameters[$typeParameter] =
                        $objectTypes.$typeParameter.ToString('D')
                }
            }
            Invoke-WindowsADCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Server $pinnedServer `
                -DistinguishedName $DistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        if (-not $objectTypes) {
            $objectTypes = Resolve-WindowsADObjectTypeGuid `
                -ObjectType $ObjectType `
                -InheritedObjectType $InheritedObjectType
        }
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ForWrite
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType Active Directory access rules")) {
                $descriptor = $target.BinarySecurityDescriptor
                foreach ($sid in $identities) {
                    $descriptor = Invoke-WindowsADAccessRuleMutation `
                        -SecurityDescriptor $descriptor `
                        -Operation Add `
                        -SecurityIdentifier $sid `
                        -AccessMask ([int]$AccessRights) `
                        -AccessControlType $AccessControlType `
                        -InheritanceType $InheritanceType `
                        -ObjectType $objectTypes.ObjectType `
                        -InheritedObjectType $objectTypes.InheritedObjectType
                }
                Set-WindowsADObjectSecurityDescriptor `
                    -Target $target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -SecurityDescriptor $descriptor `
                    -ExpectedSecurityDescriptor $target.BinarySecurityDescriptor `
                    -RequireManageableDacl
                if ($PassThru) {
                    Get-ADObjectAccessRule `
                        -Server $Server `
                        -DistinguishedName $target.DistinguishedName `
                        -Credential $Credential `
                        -Account $identities.Value `
                        -ExcludeInherited `
                        -TimeoutSeconds $TimeoutSeconds `
                        -ThrottleLimit 1 |
                        Where-Object {
                            [int]$_.AccessRights -eq [int]$AccessRights -and
                            $_.AccessControlType -eq $AccessControlType -and
                            $_.InheritanceType -eq $InheritanceType -and
                            $_.ObjectTypeGuid -eq $objectTypes.ObjectType -and
                            $_.InheritedObjectTypeGuid -eq $objectTypes.InheritedObjectType
                        }
                }
            }
        }
    }
}
