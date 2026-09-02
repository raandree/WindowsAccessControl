function Get-ADObjectCallerEffectiveAccess {
    <#
    .SYNOPSIS
        Gets the write access a domain controller computes for the calling
        identity on Active Directory objects.
    .DESCRIPTION
        Reads the three constructed attributes a domain controller evaluates in
        the security context of the LDAP bind that requested them:
        allowedAttributesEffective, allowedChildClassesEffective, and
        sDRightsEffective. The module computes none of these values; it names
        the attributes explicitly, because a wildcard attribute request never
        returns a constructed attribute, and formats what the controller
        returns.

        The result is scoped to the bound identity and to nothing else. There is
        no Account parameter, because no in-box interface asks a domain
        controller for another principal's effective access. Supplying
        Credential changes the bind and therefore changes the answer.

        The three attributes are a write-side answer. None of them reports read
        access, extended rights such as Reset Password, or the right to delete,
        move, or rename a child object. Use Get-ADObjectAccessRule to see who is
        granted what.
    .PARAMETER Server
        The explicit DNS name of the domain controller to ask. When it is
        omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to evaluate.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server. It
        selects the identity the domain controller evaluates.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .EXAMPLE
        Get-ADObjectCallerEffectiveAccess -DistinguishedName $dn

        Reports which descriptor sections, attributes, and child classes the
        current identity may write on the selected object.
    .EXAMPLE
        (Get-ADObjectCallerEffectiveAccess -DistinguishedName $dn).WritableAttribute

        Lists every attribute the domain controller says the caller may write.
    .EXAMPLE
        Get-ADObjectCallerEffectiveAccess -Server dc01.example.test `
            -DistinguishedName $dn `
            -Credential (Get-Credential)

        Asks the same controller what the supplied identity may write, because
        the constructed attributes are evaluated for whoever bound the session.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ADObjectCallerEffectiveAccess
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
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
                -ThrottleLimit $ThrottleLimit
            return
        }
        $account = if ($Credential) {
            $Credential.UserName
        }
        else {
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        $connection = New-WindowsADConnection `
            -Server $Server `
            -Credential $Credential `
            -TimeoutSeconds $TimeoutSeconds
        try {
            foreach ($dnValue in $DistinguishedName) {
                $target = Resolve-WindowsADObjectTarget `
                    -Server $Server `
                    -DistinguishedName ([string]$dnValue) `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -Connection $connection
                $record = Get-WindowsADEffectiveAccessRecord `
                    -Connection $connection `
                    -DistinguishedName $target.DistinguishedName
                ConvertTo-WindowsADEffectiveAccessObject `
                    -Target $target `
                    -Record $record `
                    -Account $account
            }
        }
        finally {
            $connection.Dispose()
        }
    }
}
