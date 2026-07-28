function Set-WindowsADObjectSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this LDAP write boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [string]$AllowedBaseDistinguishedName,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    $validatedTarget = Resolve-WindowsADObjectTarget `
        -Server $Target.Server `
        -DistinguishedName $Target.DistinguishedName `
        -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
        -Credential $Credential `
        -TimeoutSeconds $TimeoutSeconds `
        -ForWrite `
        -ExpectedObjectGuid $Target.ObjectGuid
    $requested = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    if (-not $requested.DiscretionaryAcl) {
        throw 'The Active Directory security descriptor contains a null DACL.'
    }
    $current = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $validatedTarget.BinarySecurityDescriptor,
        0
    )
    $section = [System.Security.AccessControl.AccessControlSections]::Access
    if ($current.GetSddlForm($section) -ceq $requested.GetSddlForm($section)) {
        return
    }

    $connection = New-WindowsADConnection `
        -Server $validatedTarget.Server `
        -Credential $Credential `
        -TimeoutSeconds $TimeoutSeconds
    try {
        $modification = [System.DirectoryServices.Protocols.DirectoryAttributeModification]::new()
        $modification.Name = 'nTSecurityDescriptor'
        $modification.Operation =
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $null = $modification.Add($SecurityDescriptor)
        $request = [System.DirectoryServices.Protocols.ModifyRequest]::new(
            $validatedTarget.DistinguishedName,
            $modification
        )
        $null = $request.Controls.Add(
            [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new(
                [System.DirectoryServices.Protocols.SecurityMasks]::Dacl
            )
        )
        $response = [System.DirectoryServices.Protocols.ModifyResponse](
            $connection.SendRequest($request)
        )
        if ($response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
            throw "Active Directory DACL write failed: $($response.ResultCode)."
        }
    }
    finally {
        $connection.Dispose()
    }
}
