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
        [byte[]]$SecurityDescriptor
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
    $candidateSddl = $candidate.GetSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    $result = Invoke-WindowsTaskSchedulerComOperation -Target $Target -Operation {
        param($NativeTarget)

        $currentSddl = [string]$NativeTarget.GetSecurityDescriptor(4)
        $current = [Security.AccessControl.RawSecurityDescriptor]::new($currentSddl)
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
            }
            catch {
                throw [AggregateException]::new(
                    'The Task Scheduler DACL write and rollback both failed.',
                    [Exception[]]@($writeError.Exception, $_.Exception)
                )
            }
            throw $writeError
        }
        [pscustomobject]@{ Bytes = $SecurityDescriptor }
    }
    Write-Output -InputObject ([byte[]]$result.Bytes) -NoEnumerate
}