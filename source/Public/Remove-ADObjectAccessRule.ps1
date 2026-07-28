function Remove-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Removes one exact path-bound Active Directory access rule.
    .DESCRIPTION
        Revalidates server, allowed OU, distinguished name, and object GUID,
        removes one exact explicit native ACE, and preserves unrelated object ACEs.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ADObjectAccessRule.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds the permitted mutation.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to the rule server.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -Account $sid | Remove-ADObjectAccessRule -AllowedBaseDistinguishedName $ou -WhatIf

        Previews exact removal of the selected directory ACE.
    .INPUTS
        WindowsAccessControl.ADObjectAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$InputObject,
        [Parameter(Mandatory)]
        [string]$AllowedBaseDistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.ADObjectAccessRule' -or
            -not $InputObject.NativeAce -or
            -not $InputObject.Server -or
            -not $InputObject.DistinguishedName -or
            -not $InputObject.ObjectGuid) {
            throw 'InputObject must be a path-bound rule from Get-ADObjectAccessRule.'
        }
        $target = Resolve-WindowsADObjectTarget `
            -Server $InputObject.Server `
            -DistinguishedName $InputObject.DistinguishedName `
            -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
            -Credential $Credential `
            -TimeoutSeconds $TimeoutSeconds `
            -ForWrite `
            -ExpectedObjectGuid ([guid]$InputObject.ObjectGuid)
        if ($target.CanonicalTarget -cne $InputObject.CanonicalTarget) {
            throw 'The Active Directory access rule no longer matches its immutable target.'
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact Active Directory access rule for $($InputObject.SID)")) {
            $descriptor = Invoke-WindowsADAccessRuleMutation `
                -SecurityDescriptor $target.BinarySecurityDescriptor `
                -Operation Remove `
                -NativeAce $InputObject.NativeAce
            Set-WindowsADObjectSecurityDescriptor `
                -Target $target `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -SecurityDescriptor $descriptor
            if ($PassThru) { $InputObject }
        }
    }
}
