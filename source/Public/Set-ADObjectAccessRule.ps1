function Set-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Replaces typed access rules in bounded Active Directory object DACLs.
    .DESCRIPTION
        Prevalidates identities and a disposable OU boundary, replaces every
        explicit ACE that shares the same account, qualifier, and object GUIDs
        with one new ACE, and revalidates object GUID before LDAP write. ACEs
        with a different object scope are preserved rather than flattened.
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
        Active Directory rights that replace the current rights.
    .PARAMETER AccessControlType
        Replaces Allow rules by default or explicit Deny rules.
    .PARAMETER InheritanceType
        Controls directory inheritance for the replacement ACE.
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
        Set-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights ReadProperty -WhatIf

        Previews replacing every explicit common ACE for the account inside the allowed OU.
    .EXAMPLE
        Set-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\Analysts', 'CONTOSO\Auditors' -AccessRights 'ReadProperty, WriteProperty' -Confirm:$false

        Replaces the common ACE for two groups with the same replacement rights.
    .EXAMPLE
        Set-ADObjectAccessRule -DistinguishedName $ou -AllowedBaseDistinguishedName $ou -Account $sid -AccessRights ReadProperty -ObjectType 'employeeID' -InheritanceType Descendents -InheritedObjectType 'user' -Confirm:$false

        Replaces every explicit employeeID-scoped ACE for the account with a
        single read-only ACE, leaving ACEs scoped to other attributes and any
        common ACE for the same account untouched.
    .EXAMPLE
        Set-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\Contractors' -AccessRights WriteProperty -AccessControlType Deny -Confirm:$false -PassThru

        Replaces the contractors group's explicit deny ACE so it denies only
        write-property, and returns the stored rule.
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Set $AccessControlType Active Directory access rules")) {
                $descriptor = $target.BinarySecurityDescriptor
                foreach ($sid in $identities) {
                    $descriptor = Invoke-WindowsADAccessRuleMutation `
                        -SecurityDescriptor $descriptor `
                        -Operation Set `
                        -SecurityIdentifier $sid `
                        -AccessMask ([int]$AccessRights) `
                        -AccessControlType $AccessControlType `
                        -InheritanceType $InheritanceType `
                        -ObjectType $objectTypes.ObjectType `
                        -InheritedObjectType $objectTypes.InheritedObjectType
                }
                foreach ($displaced in Get-WindowsADRemovedAccessRule `
                        -Target $target `
                        -OriginalSecurityDescriptor $target.BinarySecurityDescriptor `
                        -SecurityDescriptor $descriptor) {
                    Write-Verbose (
                        "Replacing $($displaced.AccessControlType) " +
                        "$($displaced.AccessRights) for $($displaced.SID) on " +
                        $target.CanonicalTarget
                    )
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
