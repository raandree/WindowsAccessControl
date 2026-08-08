[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseUsingScopeModifierInNewRunspaces',
    '',
    Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
)]
param()

BeforeAll {
    if ([string]::IsNullOrWhiteSpace($env:WAC_DOMAIN_LAB_MEMBER)) {
        throw 'WAC_DOMAIN_LAB_MEMBER must identify the disposable member server.'
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    Import-Module `
        -Name (Join-Path $PSScriptRoot 'WindowsAccessControl.DomainLab.psm1') `
        -ErrorAction Stop

    $script:domain = Get-ADDomain -ErrorAction Stop
    $script:server = [string]@(
        (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName
    )[0]
    $script:rootOu = "OU=WindowsAccessControlLab,$($script:domain.DistinguishedName)"
    $script:targetOu = "OU=Targets,$($script:rootOu)"
    $script:shareName = 'WacLab$'
    $script:taskFolder = '\WindowsAccessControlLab'

    # Every other suite uses a principal from the fixture domain, so nothing
    # proves that a security identifier from another domain or another forest
    # survives a write and a read. The primary group of each foreign domain is
    # used because it always exists and this suite never modifies it.
    $script:foreignPrincipals = @(
        foreach ($domainName in 'b.forest1.net', 'forest2.net') {
            $foreignDomain = Get-ADDomain -Identity $domainName -ErrorAction Stop
            [pscustomobject]@{
                Domain      = $domainName
                NetBIOSName = $foreignDomain.NetBIOSName
                Scope       = if ($foreignDomain.Forest -eq $script:domain.Forest) {
                    'CrossDomain'
                }
                else {
                    'CrossForest'
                }
                SID         = '{0}-513' -f $foreignDomain.DomainSID.Value
            }
        }
    )
    $script:crossDomainPrincipal = @(
        $script:foreignPrincipals | Where-Object Scope -EQ 'CrossDomain'
    )[0]
    $script:crossForestPrincipal = @(
        $script:foreignPrincipals | Where-Object Scope -EQ 'CrossForest'
    )[0]
    if (-not $script:crossDomainPrincipal -or -not $script:crossForestPrincipal) {
        throw 'The lab must provide one other domain in this forest and one trusted forest.'
    }

    # A well-formed account identifier from a domain that does not exist. No
    # lookup can ever resolve it, which is what an access control entry left
    # behind by a deleted principal looks like.
    $script:orphanSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'

    $script:originalDirectoryDescriptor = Get-ADObjectSecurityDescriptor `
        -Server $script:server `
        -DistinguishedName $script:targetOu `
        -ThrottleLimit 1

    $script:session = New-PSSession `
        -ComputerName $env:WAC_DOMAIN_LAB_MEMBER `
        -Authentication Kerberos `
        -ErrorAction Stop
    $script:remoteModulePath = 'C:\WindowsAccessControlLab\ForeignPrincipalModule'
    Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:remoteModulePath `
        -ScriptBlock {
            param($ModulePath)

            Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
            $null = New-Item -Path $ModulePath -ItemType Directory -Force
        }
    Copy-Item `
        -Path (Join-Path $moduleManifest.Directory.FullName '*') `
        -Destination $script:remoteModulePath `
        -ToSession $script:session `
        -Recurse `
        -Force `
        -ErrorAction Stop
    $script:remoteManifest = Join-Path $script:remoteModulePath 'WindowsAccessControl.psd1'
    $null = Enter-WindowsAccessControlMemberCoverage `
        -Session $script:session `
        -ModulePath (Join-Path $script:remoteModulePath 'WindowsAccessControl.psm1')

    $script:originalMemberDescriptors = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:remoteManifest, $script:shareName, $script:taskFolder `
        -ScriptBlock {
            param($Manifest, $ShareName, $TaskFolder)

            Import-Module $Manifest -Force -ErrorAction Stop
            [pscustomobject]@{
                Share      = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                TaskFolder = (Get-TaskFolderSecurityDescriptor -Path $TaskFolder).Sddl
            }
        }
}

AfterAll {
    try {
        if ($script:originalDirectoryDescriptor) {
            Set-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Sddl $script:originalDirectoryDescriptor.Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false
            $restoredDirectory = Get-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ThrottleLimit 1
            if ($restoredDirectory.Sddl -cne $script:originalDirectoryDescriptor.Sddl) {
                throw 'The disposable Active Directory object DACL was not restored.'
            }
        }

        if ($script:session -and $script:originalMemberDescriptors) {
            $restoredMember = Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:shareName, $script:taskFolder, $script:originalMemberDescriptors `
                -ScriptBlock {
                    param($ShareName, $TaskFolder, $Original)

                    Set-SmbShareSecurityDescriptor `
                        -Name $ShareName `
                        -Sddl $Original.Share `
                        -Confirm:$false
                    Set-TaskFolderSecurityDescriptor `
                        -Path $TaskFolder `
                        -AllowedRootPath $TaskFolder `
                        -Sddl $Original.TaskFolder `
                        -Confirm:$false
                    [pscustomobject]@{
                        Share      = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                        TaskFolder = (Get-TaskFolderSecurityDescriptor -Path $TaskFolder).Sddl
                    }
                }
            if ($restoredMember.Share -cne $script:originalMemberDescriptors.Share) {
                throw 'The disposable SMB share DACL was not restored.'
            }
            if ($restoredMember.TaskFolder -cne $script:originalMemberDescriptors.TaskFolder) {
                throw 'The disposable task-folder DACL was not restored.'
            }
        }
    }
    finally {
        if ($script:session) {
            Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:remoteModulePath `
                -ScriptBlock {
                    param($ModulePath)

                    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
                } `
                -ErrorAction SilentlyContinue
            $null = Exit-WindowsAccessControlMemberCoverage `
                -Session $script:session `
                -Name 'ForeignPrincipalPermissions.Live.Tests.ps1'
            Remove-PSSession $script:session
        }
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Foreign and orphaned principal identity' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {

    It 'Should resolve a cross-domain and a cross-forest principal and report an orphan' {
        $resolved = Resolve-WindowsIdentity -Identity @(
            $script:crossDomainPrincipal.SID
            $script:crossForestPrincipal.SID
            $script:orphanSid
        )

        $resolved | Should -HaveCount 3

        $crossDomain = $resolved[0]
        $crossDomain.IsResolved | Should -BeTrue
        $crossDomain.SID | Should -BeExactly $script:crossDomainPrincipal.SID
        $crossDomain.Account |
            Should -BeExactly "$($script:crossDomainPrincipal.NetBIOSName)\Domain Users"

        $crossForest = $resolved[1]
        $crossForest.IsResolved | Should -BeTrue
        $crossForest.SID | Should -BeExactly $script:crossForestPrincipal.SID
        $crossForest.Account |
            Should -BeExactly "$($script:crossForestPrincipal.NetBIOSName)\Domain Users"

        $orphan = $resolved[2]
        $orphan.IsResolved | Should -BeFalse
        $orphan.SID | Should -BeExactly $script:orphanSid
        $orphan.Account | Should -BeNullOrEmpty
    }
}

Describe 'Foreign and orphaned principal directory rules' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {

    It 'Should add and exactly remove a cross-forest and an orphaned directory rule' {
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1

        $added = @(
            foreach ($sid in $script:crossForestPrincipal.SID, $script:orphanSid) {
                Add-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $script:targetOu `
                    -AllowedBaseDistinguishedName $script:targetOu `
                    -Account $sid `
                    -AccessRights ReadProperty `
                    -ThrottleLimit 1 `
                    -PassThru `
                    -Confirm:$false
            }
        )

        try {
            $added | Should -HaveCount 2
            $added[0].SID | Should -BeExactly $script:crossForestPrincipal.SID
            $added[1].SID | Should -BeExactly $script:orphanSid

            $crossForestRule = @(
                Get-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $script:targetOu `
                    -Account $script:crossForestPrincipal.SID `
                    -ExcludeInherited `
                    -ThrottleLimit 1
            )
            $crossForestRule | Should -HaveCount 1
            $crossForestRule[0].IsOrphaned | Should -BeFalse
            $crossForestRule[0].Account |
                Should -BeExactly "$($script:crossForestPrincipal.NetBIOSName)\Domain Users"

            # A read must survive an entry no lookup can resolve rather than
            # failing the whole descriptor.
            $orphanRule = @(
                Get-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $script:targetOu `
                    -Account $script:orphanSid `
                    -ExcludeInherited `
                    -ThrottleLimit 1
            )
            $orphanRule | Should -HaveCount 1
            $orphanRule[0].IsOrphaned | Should -BeTrue
            $orphanRule[0].Account | Should -BeNullOrEmpty
            $orphanRule[0].SID | Should -BeExactly $script:orphanSid
        }
        finally {
            $null = $added | Remove-ADObjectAccessRule `
                -AllowedBaseDistinguishedName $script:targetOu `
                -TimeoutSeconds 10 `
                -PassThru `
                -Confirm:$false
        }

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1
        $after.Sddl | Should -BeExactly $before.Sddl
    }
}

Describe 'Foreign and orphaned principal member rules' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {

    It 'Should add and exactly remove cross-domain, cross-forest, and orphaned share rules' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:crossDomainPrincipal.SID, $script:crossForestPrincipal.SID, $script:orphanSid `
            -ScriptBlock {
                param($ShareName, $CrossDomainSid, $CrossForestSid, $OrphanSid)

                $before = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                $added = @(
                    foreach ($sid in $CrossDomainSid, $CrossForestSid, $OrphanSid) {
                        Add-SmbShareAccessRule `
                            -Name $ShareName `
                            -Account $sid `
                            -AccessRights Read `
                            -PassThru `
                            -Confirm:$false
                    }
                )
                $rules = @(Get-SmbShareAccessRule -Name $ShareName)
                $null = $added | Remove-SmbShareAccessRule -PassThru -Confirm:$false
                [pscustomobject]@{
                    Before      = $before
                    After       = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                    AddedSids   = @($added.SID)
                    Rules       = @(
                        $rules |
                            Where-Object { $_.SID -in @($CrossDomainSid, $CrossForestSid, $OrphanSid) } |
                            ForEach-Object {
                                [pscustomobject]@{
                                    SID        = $_.SID
                                    Account    = $_.Account
                                    IsOrphaned = $_.IsOrphaned
                                }
                            }
                    )
                }
            }

        @($result.AddedSids) | Should -Be @(
            $script:crossDomainPrincipal.SID
            $script:crossForestPrincipal.SID
            $script:orphanSid
        )

        $crossDomainRule = @(
            $result.Rules | Where-Object SID -EQ $script:crossDomainPrincipal.SID
        )
        $crossDomainRule | Should -HaveCount 1
        $crossDomainRule[0].IsOrphaned | Should -BeFalse
        $crossDomainRule[0].Account |
            Should -BeExactly "$($script:crossDomainPrincipal.NetBIOSName)\Domain Users"

        $crossForestRule = @(
            $result.Rules | Where-Object SID -EQ $script:crossForestPrincipal.SID
        )
        $crossForestRule | Should -HaveCount 1
        $crossForestRule[0].IsOrphaned | Should -BeFalse
        $crossForestRule[0].Account |
            Should -BeExactly "$($script:crossForestPrincipal.NetBIOSName)\Domain Users"

        $orphanRule = @($result.Rules | Where-Object SID -EQ $script:orphanSid)
        $orphanRule | Should -HaveCount 1
        $orphanRule[0].IsOrphaned | Should -BeTrue
        $orphanRule[0].Account | Should -BeNullOrEmpty

        $result.After | Should -BeExactly $result.Before
    }

    It 'Should add and exactly remove an orphaned task-folder rule' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskFolder, $script:orphanSid `
            -ScriptBlock {
                param($TaskFolder, $OrphanSid)

                $before = (Get-TaskFolderSecurityDescriptor -Path $TaskFolder).Sddl
                $added = @(
                    Add-TaskFolderAccessRule `
                        -Path $TaskFolder `
                        -AllowedRootPath $TaskFolder `
                        -Account $OrphanSid `
                        -AccessRights ReadAndTraverse `
                        -AppliesTo ThisFolderOnly `
                        -PassThru `
                        -Confirm:$false
                )
                $rule = @(
                    Get-TaskFolderAccessRule -Path $TaskFolder |
                        Where-Object SID -EQ $OrphanSid
                )
                $null = $added | Remove-TaskFolderAccessRule `
                    -AllowedRootPath $TaskFolder `
                    -PassThru `
                    -Confirm:$false
                [pscustomobject]@{
                    Before     = $before
                    After      = (Get-TaskFolderSecurityDescriptor -Path $TaskFolder).Sddl
                    AddedSid   = @($added.SID)[0]
                    RuleCount  = $rule.Count
                    Account    = @($rule.Account)[0]
                    IsOrphaned = @($rule.IsOrphaned)[0]
                }
            }

        $result.AddedSid | Should -BeExactly $script:orphanSid
        $result.RuleCount | Should -Be 1
        $result.IsOrphaned | Should -BeTrue
        $result.Account | Should -BeNullOrEmpty
        $result.After | Should -BeExactly $result.Before
    }

    It 'Should add and exactly remove an orphaned private-key rule' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:orphanSid `
            -ScriptBlock {
                param($OrphanSid)

                $certificate = @(
                    Get-ChildItem Cert:\LocalMachine\My |
                        Where-Object {
                            $_.Subject -ceq 'CN=WindowsAccessControl Lab Key' -and
                            $_.FriendlyName -ceq 'WindowsAccessControl Lab Key'
                        }
                )[0]
                $privateKey = $null
                try {
                    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                        GetRSAPrivateKey($certificate)
                    $providerName = $privateKey.Key.Provider.Provider
                    $keyName = $privateKey.Key.KeyName
                }
                finally {
                    if ($privateKey) {
                        $privateKey.Dispose()
                    }
                }
                $common = @{
                    Certificate  = $certificate
                    ProviderName = $providerName
                    KeyName      = $keyName
                }

                $before = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl
                Add-CertificatePrivateKeyAccessRule @common `
                    -Account $OrphanSid `
                    -AccessRights Read `
                    -Confirm:$false
                $rule = @(
                    Get-CertificatePrivateKeyAccessRule @common |
                        Where-Object SID -EQ $OrphanSid
                )
                Remove-CertificatePrivateKeyAccessRule @common `
                    -Account $OrphanSid `
                    -AccessRights Read `
                    -Confirm:$false
                [pscustomobject]@{
                    Before     = $before
                    After      = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl
                    RuleCount  = $rule.Count
                    Account    = @($rule.Account)[0]
                    IsOrphaned = @($rule.IsOrphaned)[0]
                }
            }

        $result.RuleCount | Should -Be 1
        $result.IsOrphaned | Should -BeTrue
        $result.Account | Should -BeNullOrEmpty
        $result.After | Should -BeExactly $result.Before
    }
}
