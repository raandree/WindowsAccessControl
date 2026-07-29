function Set-WindowsTaskSchedulerSecurityDescriptor {
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
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [byte[]]$ExpectedCurrentSecurityDescriptor
    )

    $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    if (-not $candidate.DiscretionaryAcl) {
        throw [ArgumentException]::new(
            'The Task Scheduler security descriptor requires a non-null DACL.'
        )
    }
    $expected = if ($PSBoundParameters.ContainsKey('ExpectedCurrentSecurityDescriptor')) {
        [Security.AccessControl.RawSecurityDescriptor]::new(
            $ExpectedCurrentSecurityDescriptor,
            0
        )
    }
    $candidateSddl = $candidate.GetSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    $result = Invoke-WindowsTaskSchedulerComOperation -Target $Target -Operation {
        param($NativeTarget)

        $currentSddl = [string]$NativeTarget.GetSecurityDescriptor(4)
        $current = [Security.AccessControl.RawSecurityDescriptor]::new($currentSddl)
        if ($expected -and -not (Test-WindowsTaskSchedulerDaclEquivalent `
                -Left $current `
                -Right $expected)) {
            throw [InvalidOperationException]::new(
                'The Task Scheduler DACL changed after it was read; rerun the command against the current descriptor.'
            )
        }
        if (-not (Test-WindowsTaskSchedulerSystemAce `
                -CurrentDescriptor $current `
                -CandidateDescriptor $candidate)) {
            throw [InvalidOperationException]::new(
                'The candidate Task Scheduler DACL must preserve every current SYSTEM ACE and must not add an explicit SYSTEM deny ACE.'
            )
        }
        if (Test-WindowsTaskSchedulerDaclEquivalent `
            -Left $current `
            -Right $candidate) {
            [pscustomobject]@{ Bytes = $SecurityDescriptor }
            return
        }
        $serviceTokenSids = Get-WindowsTaskSchedulerServiceTokenSid
        if (Test-WindowsTaskSchedulerServiceDenyAce `
                -CurrentDescriptor $current `
                -CandidateDescriptor $candidate `
                -ServiceTokenSid $serviceTokenSids) {
            throw [InvalidOperationException]::new(
                'The candidate Task Scheduler DACL adds a deny ACE for an identity in the Task Scheduler service token and would remove its required read, write, or run access.'
            )
        }
        Assert-WindowsTaskSchedulerAceSupport -SecurityDescriptor $candidate
        Write-WindowsTaskSchedulerDenyAceWarning `
            -CurrentDescriptor $current `
            -CandidateDescriptor $candidate `
            -ServiceTokenSid $serviceTokenSids

        $setFlags = if ($Target.ObjectType -eq 'ScheduledTask') { 16 } else { 0 }
        $writeError = $null
        try {
            $NativeTarget.SetSecurityDescriptor($candidateSddl, $setFlags)
            $storedSddl = [string]$NativeTarget.GetSecurityDescriptor(4)
            $stored = [Security.AccessControl.RawSecurityDescriptor]::new($storedSddl)
                if (-not (Test-WindowsTaskSchedulerDaclEquivalent `
                    -Left $stored `
                    -Right $candidate)) {
                throw [InvalidOperationException]::new(
                    'Task Scheduler did not persist the requested DACL exactly.'
                )
            }
        }
        catch {
            $writeError = $_
        }

        if ($writeError) {
            try {
                $NativeTarget.SetSecurityDescriptor($currentSddl, $setFlags)
                $rolledBack = [Security.AccessControl.RawSecurityDescriptor]::new(
                    [string]$NativeTarget.GetSecurityDescriptor(4)
                )
                if (-not (Test-WindowsTaskSchedulerDaclEquivalent `
                        -Left $rolledBack `
                        -Right $current)) {
                    throw [InvalidOperationException]::new(
                        'Task Scheduler did not restore the original DACL during rollback.'
                    )
                }
            }
            catch {
                throw [AggregateException]::new(
                    'The Task Scheduler DACL write failed and its rollback could not be verified; the stored descriptor state is indeterminate.',
                    [Exception[]]@($writeError.Exception, $_.Exception)
                )
            }
            throw $writeError
        }
        [pscustomobject]@{ Bytes = $SecurityDescriptor }
    }
    Write-Output -InputObject ([byte[]]$result.Bytes) -NoEnumerate
}