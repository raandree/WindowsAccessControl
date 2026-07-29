function Set-ADObjectSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets DACL descriptors on bounded Active Directory objects.
    .DESCRIPTION
        Validates SDDL, immutable object identity, protected-target rules, and
        an explicit allowed OU before replacing only the target DACL over LDAP.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller. When it
        is omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to modify.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds every permitted mutation.
    .PARAMETER Sddl
        A structurally valid SDDL document containing a non-null DACL.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .PARAMETER PassThru
        Returns the stored DACL descriptor after persistence.
    .EXAMPLE
        Set-ADObjectSecurityDescriptor -Server dc01.example.test -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Sddl $sddl -WhatIf

        Previews replacing only the selected object's DACL.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ADObjectSecurityDescriptor
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
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,
        [Parameter()]
        [pscredential]$Credential,
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
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if (-not $rawDescriptor.DiscretionaryAcl) {
            throw 'The supplied SDDL does not contain a non-null DACL.'
        }
        $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            if (-not $pinnedServer) {
                $pinnedServer = Resolve-WindowsADServer -Server $Server
            }
            $PSBoundParameters['Server'] = $pinnedServer
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
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ForWrite
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Set Active Directory object DACL')) {
                Set-WindowsADObjectSecurityDescriptor `
                    -Target $target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -SecurityDescriptor $descriptorBytes
                if ($PassThru) {
                    Get-ADObjectSecurityDescriptor `
                        -Server $Server `
                        -DistinguishedName $target.DistinguishedName `
                        -Credential $Credential `
                        -TimeoutSeconds $TimeoutSeconds `
                        -ThrottleLimit 1
                }
            }
        }
    }
}
