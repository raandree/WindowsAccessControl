function Get-ADObjectSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets DACL descriptors from Active Directory objects through an explicit DC.
    .DESCRIPTION
        Uses direct LDAP Negotiate authentication with signing and sealing to
        read one or more domain-partition object DACLs plus immutable object GUIDs.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller.
    .PARAMETER DistinguishedName
        One or more distinguished names in the selected domain partition.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .EXAMPLE
        Get-ADObjectSecurityDescriptor -Server dc01.example.test -DistinguishedName 'OU=Apps,DC=example,DC=test'

        Gets the Apps OU DACL through a signed and sealed LDAP connection.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ADObjectSecurityDescriptor
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Path')]
        [object[]]$DistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsADCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Server $Server `
                -DistinguishedName $DistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections Access `
                -SecurityDescriptor $target.BinarySecurityDescriptor `
                -TypeName 'WindowsAccessControl.ADObjectSecurityDescriptor'
        }
    }
}
