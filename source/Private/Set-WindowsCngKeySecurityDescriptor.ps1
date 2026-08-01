function Set-WindowsCngKeySecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this persistence boundary.'
    )]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [Security.Cryptography.CngKey]$Key,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedConcurrencyToken
    )

    $candidate = [Security.AccessControl.RawSecurityDescriptor]::new($SecurityDescriptor, 0)
    if (-not $candidate.DiscretionaryAcl) {
        throw [ArgumentException]::new(
            'The private-key security descriptor requires a non-null DACL.'
        )
    }

    $currentBytes = Get-WindowsCngKeySecurityDescriptor -Key $Key
    $current = [Security.AccessControl.RawSecurityDescriptor]::new($currentBytes, 0)

    if ($PSBoundParameters.ContainsKey('ExpectedConcurrencyToken')) {
        # The token comes from the caller's own earlier read, or from the read a
        # read-modify-write command took before staging. The write lock this runs
        # under is held per module instance, which in PowerShell means per
        # runspace, so the token is what covers a writer in another runspace or
        # another process.
        Assert-WindowsDescriptorUnchanged `
            -ExpectedToken $ExpectedConcurrencyToken `
            -CurrentToken (
                Get-WindowsSecurityDescriptorConcurrencyToken -Sddl (
                    $current.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)
                )
            ) `
            -Target $Target.CanonicalTarget
    }

    Assert-WindowsCngKeyAceSupport `
        -CurrentDescriptor $current `
        -CandidateDescriptor $candidate
    $protection = Test-WindowsCngKeyProtectedAce `
        -CurrentDescriptor $current `
        -CandidateDescriptor $candidate
    if (-not $protection.IsAllowed) {
        throw [InvalidOperationException]::new($protection.Reason)
    }

    # The provider writes DACL_SECURITY_INFORMATION alone, so it cannot change
    # whether the DACL is protected. Rejecting the mismatch here avoids a real
    # write to a security-critical object that could only end in a rollback.
    $protectedFlag = [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    $currentProtected = ([int]$current.ControlFlags -band $protectedFlag) -ne 0
    $candidateProtected = ([int]$candidate.ControlFlags -band $protectedFlag) -ne 0
    if ($currentProtected -ne $candidateProtected) {
        throw [NotSupportedException]::new(
            (
                'The candidate private-key DACL protection state does not match the stored DACL, ' +
                "which is $(if ($currentProtected) { 'protected' } else { 'not protected' }). " +
                'The key storage provider cannot change that state, so supply a descriptor whose ' +
                "DACL flags match the stored descriptor."
            )
        )
    }

    if (Test-WindowsCngKeyDaclEquivalent -Left $current -Right $candidate) {
        # Allow ACEs are additive, so their order cannot change an access check.
        # A DACL of allow ACEs written in another order is therefore already the
        # requested state, and refusing it would fail a converged machine. An
        # inherit-only deny applies to nothing on the key, so it does not make
        # order observable either.
        $hasDeny = @(
            $current.DiscretionaryAcl |
                Where-Object {
                    $_.AceType -eq [Security.AccessControl.AceType]::AccessDenied -and
                    ([int]$_.AceFlags -band
                        [int][Security.AccessControl.AceFlags]::InheritOnly) -eq 0
                }
        ).Count -gt 0
        if (-not $hasDeny -or
            (Test-WindowsCngKeyDaclEquivalent -Left $current -Right $candidate -Ordered)) {
            Write-Output -InputObject $currentBytes -NoEnumerate
            return
        }
        # A deny ACE makes order observable, and the provider decides the stored
        # order, so the write could not be verified and would never converge.
        throw [NotSupportedException]::new(
            (
                'The candidate private-key DACL contains the same ACEs as the stored DACL in a ' +
                'different order while a deny ACE is present, so the order changes the access ' +
                'check. The key storage provider decides the stored ACE order, so an ordering ' +
                'change cannot be persisted or verified.'
            )
        )
    }

    Assert-WindowsCngKeyCriticalBinding -Certificate $Certificate

    $daclAndSilent = [Security.Cryptography.CngPropertyOptions]68
    $writeError = $null
    try {
        $Key.SetProperty(
            [Security.Cryptography.CngProperty]::new(
                'Security Descr',
                $SecurityDescriptor,
                $daclAndSilent
            )
        )
        $storedBytes = Get-WindowsCngKeySecurityDescriptor -Key $Key
        $stored = [Security.AccessControl.RawSecurityDescriptor]::new($storedBytes, 0)
        if (-not (Test-WindowsCngKeyDaclEquivalent -Left $stored -Right $candidate)) {
            throw [InvalidOperationException]::new(
                'The key storage provider did not persist the requested private-key DACL.'
            )
        }
    }
    catch {
        $writeError = $_
    }

    if ($writeError) {
        try {
            $Key.SetProperty(
                [Security.Cryptography.CngProperty]::new(
                    'Security Descr',
                    $currentBytes,
                    $daclAndSilent
                )
            )
            $rolledBack = [Security.AccessControl.RawSecurityDescriptor]::new(
                (Get-WindowsCngKeySecurityDescriptor -Key $Key),
                0
            )
            if (-not (Test-WindowsCngKeyDaclEquivalent -Left $rolledBack -Right $current)) {
                throw [InvalidOperationException]::new(
                    'The key storage provider did not restore the original private-key DACL during rollback.'
                )
            }
        }
        catch {
            throw [AggregateException]::new(
                'The private-key DACL write failed and its rollback could not be verified; the stored descriptor state is indeterminate.',
                [Exception[]]@($writeError.Exception, $_.Exception)
            )
        }
        throw $writeError
    }

    Write-Output -InputObject (Get-WindowsCngKeySecurityDescriptor -Key $Key) -NoEnumerate
}
