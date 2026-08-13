[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseUsingScopeModifierInNewRunspaces',
    '',
    Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
)]
param()

BeforeAll {
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

    $moduleRoot = & (Join-Path $PSScriptRoot 'Resolve-WindowsAccessControlLabModuleRoot.ps1')
    Import-Module -Name (Join-Path $moduleRoot 'WindowsAccessControl.psd1') -Force -ErrorAction Stop

    $script:domain = Get-ADDomain -ErrorAction Stop
    $script:writableControllers = @(
        Get-ADDomainController -Filter 'IsReadOnly -eq $false' -Server $script:domain.DNSRoot -ErrorAction Stop |
            Sort-Object -Property HostName |
            Select-Object -ExpandProperty HostName
    )
    if ($script:writableControllers.Count -lt 2) {
        throw (
            'This suite requires two writable domain controllers in ' +
            "'$($script:domain.DNSRoot)' but found $($script:writableControllers.Count)."
        )
    }
    $script:primaryServer = $script:writableControllers[0]
    $script:partnerServer = $script:writableControllers[1]
    $script:partnerComputerName = $script:partnerServer.Split('.')[0]

    $script:rootOu = "OU=WindowsAccessControlLab,$($script:domain.DistinguishedName)"
    $script:targetOu = "OU=Targets,$($script:rootOu)"
    $script:testSid = (Get-ADUser -Identity 'WacLabUser' -ErrorAction Stop).SID.Value
    $script:competingSid = (Get-ADUser -Identity 'WacLabOperator' -ErrorAction Stop).SID.Value
    $script:createdOrganizationalUnits = [Collections.Generic.List[string]]::new()

    # The fixture is recreated at the start of every acceptance run, and the
    # partner does not necessarily replicate it before this suite runs. Every
    # assertion here compares the two controllers, so the partner is made
    # current for the fixture first; otherwise the suite reports the previous
    # run's object and fails for a reason that is not the module's.
    foreach ($fixtureObject in $script:rootOu, $script:targetOu) {
        Sync-ADObject `
            -Object $fixtureObject `
            -Source $script:primaryServer `
            -Destination $script:partnerServer `
            -ErrorAction Stop
    }

    function script:New-DisposableOrganizationalUnit {
        param([string]$Name, [string]$Path = $script:targetOu)

        $null = New-ADOrganizationalUnit `
            -Name $Name `
            -Path $Path `
            -Server $script:primaryServer `
            -ProtectedFromAccidentalDeletion:$false `
            -ErrorAction Stop
        $distinguishedName = "OU=$Name,$Path"
        $script:createdOrganizationalUnits.Add($distinguishedName)
        $distinguishedName
    }

    function script:Sync-DisposableObject {
        param([string]$DistinguishedName, [string]$From, [string]$To)

        # The partner replicates on its own schedule and these objects are
        # created minutes earlier in the same run, so syncing the object alone
        # fails on a parent the partner has never seen. Push the chain from the
        # fixture root down, then the object itself.
        $chain = [Collections.Generic.List[string]]::new()
        $current = $DistinguishedName
        while ($current -and $current -ne $script:domain.DistinguishedName) {
            $chain.Insert(0, $current)
            if ($current -eq $script:rootOu) { break }
            $separator = $current.IndexOf(',')
            if ($separator -lt 0) { break }
            $current = $current.Substring($separator + 1)
        }
        foreach ($link in $chain) {
            Sync-ADObject `
                -Object $link `
                -Source $From `
                -Destination $To `
                -ErrorAction Stop
        }
    }

    function script:New-StaleDaclSddl {
        param([string]$BaselineSddl, [string]$Sid)

        # A competing writer computes its descriptor from the read it already
        # holds. Rebuilding the DACL from that baseline is what makes the write
        # deterministically stale, regardless of what replication delivered in
        # the meantime.
        $security = [DirectoryServices.ActiveDirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm(
            $BaselineSddl,
            [Security.AccessControl.AccessControlSections]::Access)
        $security.AddAccessRule(
            [DirectoryServices.ActiveDirectoryAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($Sid),
                [DirectoryServices.ActiveDirectoryRights]::ReadProperty,
                [Security.AccessControl.AccessControlType]::Allow))
        $security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access)
    }

    function script:Wait-DirectoryConvergence {
        param([string]$DistinguishedName, [int]$Attempts = 10)

        # Two writes made from the same base carry the same attribute version,
        # so the winner is settled by the receiving controller rather than by
        # the order of these calls. Push both ways until both controllers report
        # the same DACL.
        for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
            script:Sync-DisposableObject -DistinguishedName $DistinguishedName `
                -From $script:primaryServer -To $script:partnerServer
            script:Sync-DisposableObject -DistinguishedName $DistinguishedName `
                -From $script:partnerServer -To $script:primaryServer

            $onPrimary = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $DistinguishedName `
                -ThrottleLimit 1
            $onPartner = Get-ADObjectSecurityDescriptor `
                -Server $script:partnerServer `
                -DistinguishedName $DistinguishedName `
                -ThrottleLimit 1

            if ($onPrimary.Sddl -ceq $onPartner.Sddl) {
                return [pscustomobject]@{
                    Converged = $true
                    Attempts  = $attempt
                    Primary   = $onPrimary
                    Partner   = $onPartner
                }
            }

            Start-Sleep -Seconds 2
        }

        [pscustomobject]@{
            Converged = $false
            Attempts  = $Attempts
            Primary   = $onPrimary
            Partner   = $onPartner
        }
    }

    function script:Restore-PartnerDirectoryService {
        param([string[]]$Dependent = @(), [int]$TimeoutSeconds = 240)

        Invoke-Command `
            -ComputerName $script:partnerComputerName `
            -Authentication Kerberos `
            -ArgumentList (, $Dependent) `
            -ScriptBlock {
                param($Services)

                Start-Service -Name NTDS -ErrorAction Stop
                foreach ($name in $Services) {
                    Start-Service -Name $name -ErrorAction SilentlyContinue
                }
            } `
            -ErrorAction Stop

        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
        while ([datetime]::UtcNow -lt $deadline) {
            try {
                $null = Get-ADObjectSecurityDescriptor `
                    -Server $script:partnerServer `
                    -DistinguishedName $script:targetOu `
                    -ThrottleLimit 1
                return $true
            }
            catch {
                Start-Sleep -Seconds 5
            }
        }
        $false
    }
}

AfterAll {
    foreach ($distinguishedName in @($script:createdOrganizationalUnits)) {
        Remove-ADOrganizationalUnit `
            -Identity $distinguishedName `
            -Server $script:primaryServer `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    $leaked = @(
        Get-ADOrganizationalUnit `
            -Filter "Name -like 'WacRepl*'" `
            -SearchBase $script:targetOu `
            -Server $script:primaryServer `
            -ErrorAction SilentlyContinue
    )
    if ($leaked.Count -gt 0) {
        throw "The replication suite leaked $($leaked.Count) disposable organizational units."
    }

    # The outage test stops a directory service. Leaving a domain controller
    # down would silently degrade every later suite, so the suite fails loudly
    # rather than exiting green on a half-recovered lab.
    $partnerHealthy = $false
    try {
        $null = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1
        $partnerHealthy = $true
    }
    catch {
        $partnerHealthy = $false
    }
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    if (-not $partnerHealthy) {
        throw "The replication partner '$($script:partnerServer)' does not serve the directory after the suite."
    }
}

Describe 'Active Directory multi-controller identity' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should pin each explicit domain controller and report one immutable identity' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplIdentity'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $primary = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1
        $partner = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1

        $script:primaryServer | Should -Not -BeExactly $script:partnerServer
        $primary.ObjectGuid | Should -Be $partner.ObjectGuid
        $primary.Sddl | Should -BeExactly $partner.Sddl
        $primary.CanonicalTarget | Should -BeExactly (
            'ADObject:{0}:{1}' -f
                $script:primaryServer.ToUpperInvariant(),
                $primary.ObjectGuid.ToString('D').ToUpperInvariant()
        )
        $partner.CanonicalTarget | Should -BeExactly (
            'ADObject:{0}:{1}' -f
                $script:partnerServer.ToUpperInvariant(),
                $partner.ObjectGuid.ToString('D').ToUpperInvariant()
        )
        $primary.CanonicalTarget | Should -Not -BeExactly $partner.CanonicalTarget
    }

    It 'Should converge a rule change written on one controller to its replication partner' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplConverge'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $beforeOnPartner = Get-ADObjectAccessRule `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -Account $script:testSid `
            -ThrottleLimit 1

        Add-ADObjectAccessRule `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $afterAddOnPartner = @(
            Get-ADObjectAccessRule `
                -Server $script:partnerServer `
                -DistinguishedName $organizationalUnit `
                -Account $script:testSid `
                -ThrottleLimit 1
        )

        Remove-ADObjectAccessRule `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:partnerServer -To $script:primaryServer

        $afterRemoveOnPrimary = @(
            Get-ADObjectAccessRule `
                -Server $script:primaryServer `
                -DistinguishedName $organizationalUnit `
                -Account $script:testSid `
                -ThrottleLimit 1
        )

        @($beforeOnPartner).Count | Should -Be 0
        $afterAddOnPartner.Count | Should -Be 1
        $afterAddOnPartner[0].IsInherited | Should -BeFalse
        $afterRemoveOnPrimary.Count | Should -Be 0
    }

    It 'Should keep the immutable identity across a rename and a move' {
        $parentOu = script:New-DisposableOrganizationalUnit -Name 'WacReplParent'
        $original = script:New-DisposableOrganizationalUnit -Name 'WacReplRename' -Path $parentOu

        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $original `
            -ThrottleLimit 1

        Rename-ADObject `
            -Identity $original `
            -NewName 'WacReplRenamed' `
            -Server $script:primaryServer `
            -ErrorAction Stop
        $renamed = "OU=WacReplRenamed,$parentOu"
        $script:createdOrganizationalUnits.Remove($original) | Out-Null
        $script:createdOrganizationalUnits.Add($renamed)

        $afterRename = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $renamed `
            -ThrottleLimit 1

        $staleReadFailed = $false
        try {
            $null = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $original `
                -ThrottleLimit 1
        }
        catch {
            $staleReadFailed = $true
        }

        Move-ADObject `
            -Identity $renamed `
            -TargetPath $script:targetOu `
            -Server $script:primaryServer `
            -ErrorAction Stop
        $moved = "OU=WacReplRenamed,$($script:targetOu)"
        $script:createdOrganizationalUnits.Remove($renamed) | Out-Null
        $script:createdOrganizationalUnits.Add($moved)

        $afterMove = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $moved `
            -ThrottleLimit 1

        $afterRename.ObjectGuid | Should -Be $before.ObjectGuid
        $afterMove.ObjectGuid | Should -Be $before.ObjectGuid
        $afterMove.CanonicalTarget | Should -BeExactly $before.CanonicalTarget
        $staleReadFailed | Should -BeTrue
    }

    It 'Should reject a restore whose distinguished name was reused by a different object' {
        $name = 'WacReplReuse'
        $distinguishedName = script:New-DisposableOrganizationalUnit -Name $name
        $backupPath = Join-Path $env:TEMP (
            'wac-ad-reuse-{0}.json' -f [guid]::NewGuid().ToString('N')
        )
        try {
            $original = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $distinguishedName `
                -ThrottleLimit 1
            $original | Backup-WindowsSecurityDescriptor `
                -DestinationPath $backupPath `
                -Confirm:$false

            Remove-ADOrganizationalUnit `
                -Identity $distinguishedName `
                -Server $script:primaryServer `
                -Confirm:$false `
                -ErrorAction Stop
            $script:createdOrganizationalUnits.Remove($distinguishedName) | Out-Null

            $null = New-ADOrganizationalUnit `
                -Name $name `
                -Path $script:targetOu `
                -Server $script:primaryServer `
                -ProtectedFromAccidentalDeletion:$false `
                -ErrorAction Stop
            $script:createdOrganizationalUnits.Add($distinguishedName)
            $replacement = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $distinguishedName `
                -ThrottleLimit 1

            $restoreError = $null
            try {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $backupPath `
                    -Server $script:primaryServer `
                    -AllowedBaseDistinguishedName $script:targetOu `
                    -Confirm:$false
            }
            catch {
                $restoreError = $_.Exception.Message
            }

            $replacement.ObjectGuid | Should -Not -Be $original.ObjectGuid
            $restoreError | Should -Not -BeNullOrEmpty
        }
        finally {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should fail a read of a deleted object instead of returning an empty result' {
        $name = 'WacReplDeleted'
        $distinguishedName = script:New-DisposableOrganizationalUnit -Name $name
        Remove-ADOrganizationalUnit `
            -Identity $distinguishedName `
            -Server $script:primaryServer `
            -Confirm:$false `
            -ErrorAction Stop
        $script:createdOrganizationalUnits.Remove($distinguishedName) | Out-Null

        $readError = $null
        $result = $null
        try {
            $result = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $distinguishedName `
                -ThrottleLimit 1
        }
        catch {
            $readError = $_.Exception.Message
        }

        $result | Should -BeNullOrEmpty
        $readError | Should -Not -BeNullOrEmpty
    }
}

Describe 'Active Directory concurrent writers' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should report one content-derived concurrency token from both controllers' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplToken'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $primary = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1
        $partner = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1
        $primaryAgain = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1

        $primary.ConcurrencyToken | Should -Not -BeNullOrEmpty
        $primary.ConcurrencyToken | Should -BeExactly $partner.ConcurrencyToken `
            -Because 'the token is a hash of the read sections, not of the controller that served them'
        $primaryAgain.ConcurrencyToken | Should -BeExactly $primary.ConcurrencyToken `
            -Because 'an unchanged descriptor must produce a stable token'
        $primary.CanonicalTarget | Should -Not -BeExactly $partner.CanonicalTarget
    }

    It 'Should change the token a caller compares after another controller wrote' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplDrift'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1

        Add-ADObjectAccessRule `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Account $script:competingSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1

        $after.ObjectGuid | Should -Be $before.ObjectGuid
        $after.ConcurrencyToken | Should -Not -BeExactly $before.ConcurrencyToken `
            -Because 'comparing the token is the only staleness check an Active Directory caller has'
    }

    It 'Should discard one of two concurrent controller writes because the descriptor is one replicated attribute' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplConcurrent'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        $baselineOnPrimary = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1
        $baselineOnPartner = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $organizationalUnit `
            -ThrottleLimit 1

        Add-ADObjectAccessRule `
            -Server $script:primaryServer `
            -DistinguishedName $organizationalUnit `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false

        # The competing writer still holds the descriptor it read before that
        # write and is never told the token no longer matches, because no
        # Active Directory write command offers a staleness gate.
        $staleWriteError = $null
        try {
            Set-ADObjectSecurityDescriptor `
                -Server $script:partnerServer `
                -DistinguishedName $organizationalUnit `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Sddl (
                    script:New-StaleDaclSddl `
                        -BaselineSddl $baselineOnPartner.Sddl `
                        -Sid $script:competingSid
                ) `
                -ThrottleLimit 1 `
                -Confirm:$false
        }
        catch {
            $staleWriteError = $_.Exception.Message
        }

        $convergence = script:Wait-DirectoryConvergence -DistinguishedName $organizationalUnit
        $survivors = @(
            $script:testSid, $script:competingSid | ForEach-Object {
                @(
                    Get-ADObjectAccessRule `
                        -Server $script:primaryServer `
                        -DistinguishedName $organizationalUnit `
                        -Account $_ `
                        -ThrottleLimit 1
                ).Count
            }
        )

        $baselineOnPartner.ConcurrencyToken | Should -BeExactly $baselineOnPrimary.ConcurrencyToken
        $staleWriteError | Should -BeNullOrEmpty `
            -Because 'the stale write is accepted, which is the behavior under test'
        $convergence.Converged | Should -BeTrue `
            -Because 'the outcome may only be read once both controllers agree'
        $convergence.Partner.ConcurrencyToken | Should -BeExactly $convergence.Primary.ConcurrencyToken
        ($survivors -join ',') | Should -BeIn @('1,0', '0,1') `
            -Because 'the security descriptor replicates as one attribute, so the losing writer''s edit is discarded whole'
    }

    It 'Should keep both edits when the writers are serialized through one pinned controller' {
        $organizationalUnit = script:New-DisposableOrganizationalUnit -Name 'WacReplSerialized'
        script:Sync-DisposableObject -DistinguishedName $organizationalUnit `
            -From $script:primaryServer -To $script:partnerServer

        foreach ($account in $script:testSid, $script:competingSid) {
            Add-ADObjectAccessRule `
                -Server $script:primaryServer `
                -DistinguishedName $organizationalUnit `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Account $account `
                -AccessRights ReadProperty `
                -ThrottleLimit 1 `
                -Confirm:$false
        }

        $convergence = script:Wait-DirectoryConvergence -DistinguishedName $organizationalUnit
        $survivors = @(
            $script:testSid, $script:competingSid | ForEach-Object {
                @(
                    Get-ADObjectAccessRule `
                        -Server $script:partnerServer `
                        -DistinguishedName $organizationalUnit `
                        -Account $_ `
                        -ThrottleLimit 1
                ).Count
            }
        )

        $convergence.Converged | Should -BeTrue
        $survivors -join ',' | Should -BeExactly '1,1' `
            -Because 'a read-modify-write on one pinned controller sees the previous edit'
    }
}

Describe 'Active Directory pinned-controller outage' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should fail a pinned read and write instead of redirecting to a surviving controller' {
        $dependents = @(
            Invoke-Command `
                -ComputerName $script:partnerComputerName `
                -Authentication Kerberos `
                -ScriptBlock {
                    @(
                        (Get-Service NTDS).DependentServices |
                            Where-Object Status -EQ 'Running' |
                            Select-Object -ExpandProperty Name
                    )
                } `
                -ErrorAction Stop
        )
        $pinnedReadError = $null
        $pinnedReadResult = $null
        $pinnedWriteError = $null
        $survivor = $null
        $recovered = $false

        try {
            Invoke-Command `
                -ComputerName $script:partnerComputerName `
                -Authentication Kerberos `
                -ScriptBlock { Stop-Service -Name NTDS -Force -ErrorAction Stop } `
                -ErrorAction Stop

            try {
                $pinnedReadResult = Get-ADObjectSecurityDescriptor `
                    -Server $script:partnerServer `
                    -DistinguishedName $script:targetOu `
                    -ThrottleLimit 1
            }
            catch {
                $pinnedReadError = $_.Exception.Message
            }

            try {
                Add-ADObjectAccessRule `
                    -Server $script:partnerServer `
                    -DistinguishedName $script:targetOu `
                    -AllowedBaseDistinguishedName $script:targetOu `
                    -Account $script:testSid `
                    -AccessRights ReadProperty `
                    -ThrottleLimit 1 `
                    -Confirm:$false
            }
            catch {
                $pinnedWriteError = $_.Exception.Message
            }

            $survivor = Get-ADObjectSecurityDescriptor `
                -Server $script:primaryServer `
                -DistinguishedName $script:targetOu `
                -ThrottleLimit 1
        }
        finally {
            $recovered = script:Restore-PartnerDirectoryService -Dependent $dependents
        }

        $pinnedReadResult | Should -BeNullOrEmpty -Because 'a pinned controller that is down must not be replaced silently'
        $pinnedReadError | Should -BeLike '*LDAP server is unavailable*'
        $pinnedWriteError | Should -BeLike '*LDAP server is unavailable*'
        $survivor.CanonicalTarget | Should -BeLike "ADObject:$($script:primaryServer.ToUpperInvariant()):*"
        $recovered | Should -BeTrue -Because 'the suite must leave both controllers serving the directory'
    }

    It 'Should read the same immutable identity from both controllers after recovery' {
        $primary = Get-ADObjectSecurityDescriptor `
            -Server $script:primaryServer `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1
        $partner = Get-ADObjectSecurityDescriptor `
            -Server $script:partnerServer `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1

        $partner.ObjectGuid | Should -Be $primary.ObjectGuid
        $partner.Sddl | Should -BeExactly $primary.Sddl
    }
}
