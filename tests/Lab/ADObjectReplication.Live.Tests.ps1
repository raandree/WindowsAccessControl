[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseUsingScopeModifierInNewRunspaces',
    '',
    Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
)]
param()

BeforeAll {
    Import-Module ActiveDirectory -ErrorAction Stop

    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

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
    $script:createdOrganizationalUnits = [Collections.Generic.List[string]]::new()

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

        Sync-ADObject `
            -Object $DistinguishedName `
            -Source $From `
            -Destination $To `
            -ErrorAction Stop
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
