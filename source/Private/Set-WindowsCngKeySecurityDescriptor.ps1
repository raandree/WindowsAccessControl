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
        # The token comes from the caller's own earlier read, so this detects a
        # change made between that read and this write. Comparing two reads
        # taken inside this write lock would prove nothing.
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

    if (Test-WindowsCngKeyDaclEquivalent -Left $current -Right $candidate) {
        Write-Output -InputObject $currentBytes -NoEnumerate
        return
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
