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

    $script:session = New-PSSession `
        -ComputerName $env:WAC_DOMAIN_LAB_MEMBER `
        -Authentication Kerberos `
        -ErrorAction Stop
    $script:remoteModulePath = 'C:\WindowsAccessControlLab\ModuleUnderTest'
    Invoke-Command -Session $script:session -ArgumentList $script:remoteModulePath -ScriptBlock {
        param($ModulePath)

        Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-Item -Path $ModulePath -ItemType Directory -Force
    }
    $moduleSource = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*" |
        Sort-Object -Property { [version]$_.Name } -Descending |
        Select-Object -First 1
    Copy-Item `
        -Path (Join-Path $moduleSource.FullName '*') `
        -Destination $script:remoteModulePath `
        -ToSession $script:session `
        -Recurse `
        -Force `
        -ErrorAction Stop
    $script:remoteManifest = Join-Path $script:remoteModulePath 'WindowsAccessControl.psd1'
    Import-Module `
        -Name (Join-Path $PSScriptRoot 'WindowsAccessControl.DomainLab.psm1') `
        -ErrorAction Stop
    $null = Enter-WindowsAccessControlMemberCoverage `
        -Session $script:session `
        -ModulePath (Join-Path $script:remoteModulePath 'WindowsAccessControl.psm1')
}

AfterAll {
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
            -Name 'CertificatePrivateKeyPermissions.Live.Tests.ps1'
        Remove-PSSession $script:session
    }
}

Describe 'Certificate private-key DACL inspection' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should read the exact non-exportable software CNG key without disposing the certificate' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest `
            -ScriptBlock {
                param($Manifest)

                Import-Module $Manifest -Force -ErrorAction Stop
                $certificate = @(
                    Get-ChildItem Cert:\LocalMachine\My |
                        Where-Object {
                            $_.Subject -ceq 'CN=WindowsAccessControl Lab Key' -and
                            $_.FriendlyName -ceq 'WindowsAccessControl Lab Key'
                        }
                )
                if ($certificate.Count -ne 1) {
                    throw "Expected one disposable CNG certificate, found $($certificate.Count)."
                }
                $privateKey = $null
                try {
                    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                        GetRSAPrivateKey($certificate[0])
                    $providerName = $privateKey.Key.Provider.Provider
                    $keyName = $privateKey.Key.KeyName
                }
                finally {
                    if ($privateKey) {
                        $privateKey.Dispose()
                    }
                }

                $descriptor = $certificate[0] |
                    Get-CertificatePrivateKeySecurityDescriptor `
                        -ProviderName $providerName `
                        -KeyName $keyName
                $certificateStillUsable = -not [string]::IsNullOrWhiteSpace(
                    $certificate[0].Thumbprint
                )
                [pscustomobject]@{
                    Descriptor = $descriptor
                    ProviderName = $providerName
                    KeyName = $keyName
                    CertificateStillUsable = $certificateStillUsable
                }
            }

        $descriptor = $result.Descriptor
        $descriptor.PSObject.TypeNames | Should -Contain (
            'Deserialized.WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
        )
        $descriptor.ProviderName | Should -BeExactly $result.ProviderName
        $descriptor.KeyName | Should -BeExactly $result.KeyName
        $descriptor.KeyScope | Should -BeExactly 'Machine'
        $descriptor.Server | Should -Be $env:WAC_DOMAIN_LAB_MEMBER
        $descriptor.CanonicalTarget |
            Should -Match '^CertificatePrivateKey:Cng:Machine:[0-9A-F]{64}$'
        $descriptor.Sddl | Should -Match '^D:'
        $descriptor.BinarySecurityDescriptor.Count | Should -BeGreaterThan 0
        $descriptor.PSObject.Properties.Name | Should -Not -Contain 'PrivateKey'
        $result.CertificateStillUsable | Should -BeTrue
    }
}

Describe 'Certificate private-key DACL mutation' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should add, exactly remove, and refuse an unsafe private-key rule change' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest `
            -ScriptBlock {
                param($Manifest)

                Import-Module $Manifest -Force -ErrorAction Stop
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

                $originalSddl = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl
                $originalRules = @(Get-CertificatePrivateKeyAccessRule @common)

                Add-CertificatePrivateKeyAccessRule @common `
                    -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                $addedRules = @(Get-CertificatePrivateKeyAccessRule @common)

                Add-CertificatePrivateKeyAccessRule @common `
                    -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                $idempotentRules = @(Get-CertificatePrivateKeyAccessRule @common)

                Remove-CertificatePrivateKeyAccessRule @common `
                    -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                $restoredSddl = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl

                $systemRefusal = $null
                try {
                    Remove-CertificatePrivateKeyAccessRule @common `
                        -Account 'NT AUTHORITY\SYSTEM' `
                        -AccessRights FullControl `
                        -Confirm:$false
                }
                catch {
                    $systemRefusal = $_.Exception.Message
                }

                $denyRefusal = $null
                try {
                    Set-CertificatePrivateKeySecurityDescriptor @common `
                        -Sddl 'D:P(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)' `
                        -Confirm:$false
                }
                catch {
                    $denyRefusal = $_.Exception.Message
                }

                $conditionalRefusal = $null
                try {
                    Set-CertificatePrivateKeySecurityDescriptor @common `
                        -Sddl 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))(XA;;FA;;;BA;(@USER.Title=="x"))' `
                        -Confirm:$false
                }
                catch {
                    $conditionalRefusal = $_.Exception.Message
                }

                $providerRefusal = $null
                try {
                    $null = Get-CertificatePrivateKeyAccessRule `
                        -Certificate $certificate `
                        -ProviderName 'Microsoft Smart Card Key Storage Provider' `
                        -KeyName $keyName
                }
                catch {
                    $providerRefusal = $_.Exception.Message
                }

                $staleToken = (Get-CertificatePrivateKeySecurityDescriptor @common).ConcurrencyToken
                Add-CertificatePrivateKeyAccessRule @common `
                    -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                $staleTokenRefusal = $null
                try {
                    Set-CertificatePrivateKeySecurityDescriptor @common `
                        -Sddl $originalSddl `
                        -ConcurrencyToken $staleToken `
                        -Confirm:$false
                }
                catch {
                    $staleTokenRefusal = $_.Exception.Message
                }

                Set-CertificatePrivateKeySecurityDescriptor @common `
                    -Sddl $originalSddl -Confirm:$false
                $setRestoredSddl = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl

                Add-CertificatePrivateKeyAccessRule @common `
                    -Account 'BUILTIN\Users' -AccessRights Read -WhatIf
                $whatIfSddl = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl

                $rdpThumbprint = (
                    Get-CimInstance `
                        -Namespace 'root/cimv2/TerminalServices' `
                        -ClassName 'Win32_TSGeneralSetting'
                ).SSLCertificateSHA1Hash

                # Binding the fixture certificate to a disposable HTTP.sys port
                # is the only way to exercise the refusal deterministically. The
                # machine's own Remote Desktop certificate cannot be used: which
                # store holds it varies by machine, and it must stay bound.
                $bindingsBefore = @(
                    Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate
                ).Count
                $netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
                $bindingPort = 48443
                $bindingApplicationId = '{6f1cbf6b-1c1a-4d1e-9d2e-4c1b4d3f5a20}'
                $boundBindings = @()
                $boundRefusal = $null
                try {
                    $null = & $netshPath http add sslcert `
                        "ipport=0.0.0.0:$bindingPort" `
                        "certhash=$($certificate.Thumbprint)" `
                        "appid=$bindingApplicationId" `
                        'certstorename=MY' 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "Unable to create the disposable HTTP.sys binding; netsh returned $LASTEXITCODE."
                    }
                    $boundBindings = @(
                        Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate |
                            ForEach-Object { $_.Binding }
                    )
                    try {
                        Add-CertificatePrivateKeyAccessRule @common `
                            -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                    }
                    catch {
                        $boundRefusal = $_.Exception.Message
                    }
                }
                finally {
                    $null = & $netshPath http delete sslcert "ipport=0.0.0.0:$bindingPort" 2>&1
                }
                $bindingsAfter = @(
                    Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate
                ).Count

                $releasedWriteSucceeded = $false
                try {
                    Add-CertificatePrivateKeyAccessRule @common `
                        -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                    Remove-CertificatePrivateKeyAccessRule @common `
                        -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                    $releasedWriteSucceeded = $true
                }
                catch {
                    $releasedWriteSucceeded = $false
                }

                [pscustomobject]@{
                    OriginalRuleCount      = $originalRules.Count
                    AddedRuleCount         = $addedRules.Count
                    AddedUsersRights       = [string](
                        $addedRules | Where-Object SID -EQ 'S-1-5-32-545'
                    ).AccessRights
                    IdempotentCount        = $idempotentRules.Count
                    OriginalSddl           = $originalSddl
                    RestoredSddl           = $restoredSddl
                    SetRestoredSddl        = $setRestoredSddl
                    WhatIfSddl             = $whatIfSddl
                    SystemRefusal          = $systemRefusal
                    DenyRefusal            = $denyRefusal
                    ConditionalRefusal     = $conditionalRefusal
                    ProviderRefusal        = $providerRefusal
                    StaleTokenRefusal      = $staleTokenRefusal
                    RdpThumbprintPresent   = -not [string]::IsNullOrWhiteSpace($rdpThumbprint)
                    BindingsBefore         = $bindingsBefore
                    BoundBindings          = $boundBindings
                    BoundRefusal           = $boundRefusal
                    BindingsAfter          = $bindingsAfter
                    ReleasedWriteSucceeded = $releasedWriteSucceeded
                    FinalSddl              = (Get-CertificatePrivateKeySecurityDescriptor @common).Sddl
                }
            }

        $result.OriginalRuleCount | Should -BeGreaterOrEqual 2
        $result.AddedRuleCount | Should -Be ($result.OriginalRuleCount + 1)
        $result.AddedUsersRights | Should -BeExactly 'Read'
        $result.IdempotentCount | Should -Be $result.AddedRuleCount
        $result.RestoredSddl | Should -BeExactly $result.OriginalSddl
        $result.SetRestoredSddl | Should -BeExactly $result.OriginalSddl
        $result.WhatIfSddl | Should -BeExactly $result.OriginalSddl
        $result.SystemRefusal | Should -BeLike '*full control*'
        $result.DenyRefusal | Should -BeLike '*adds a deny ACE*'
        $result.ConditionalRefusal | Should -BeLike '*Only plain allow and deny ACEs*'
        $result.ProviderRefusal | Should -BeLike '*not admitted*'
        $result.StaleTokenRefusal | Should -BeLike '*changed after they were read*'
        $result.RdpThumbprintPresent | Should -BeTrue
        $result.BindingsBefore | Should -Be 0
        $result.BoundBindings | Should -Contain 'HttpSys'
        $result.BoundRefusal | Should -BeLike '*serves a critical binding*'
        $result.BindingsAfter | Should -Be 0
        $result.ReleasedWriteSucceeded | Should -BeTrue
        $result.FinalSddl | Should -BeExactly $result.OriginalSddl
    }
}

Describe 'Certificate private-key portability and desired state' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    BeforeAll {
        $script:resolveFixture = {
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
                [pscustomobject]@{
                    Certificate  = $certificate
                    ProviderName = $privateKey.Key.Provider.Provider
                    KeyName      = $privateKey.Key.KeyName
                }
            }
            finally {
                if ($privateKey) {
                    $privateKey.Dispose()
                }
            }
        }
    }

    It 'Should round-trip the private-key DACL through a computer-scoped record' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest, $script:resolveFixture.ToString() `
            -ScriptBlock {
                param($Manifest, $ResolveFixture)

                Import-Module $Manifest -Force -ErrorAction Stop
                $fixture = & ([scriptblock]::Create($ResolveFixture))
                # The capture is certificate-addressed, which is how an operator
                # takes a backup, and the restore is key-addressed, which is the
                # only selector a record can carry.
                $capture = @{
                    Certificate  = $fixture.Certificate
                    ProviderName = $fixture.ProviderName
                    KeyName      = $fixture.KeyName
                }
                $relocate = @{
                    ProviderName = $fixture.ProviderName
                    KeyName      = $fixture.KeyName
                    KeyScope     = 'Machine'
                }

                $backupPath = Join-Path $env:TEMP (
                    'wac-key-backup-{0}.json' -f [guid]::NewGuid().ToString('N')
                )
                try {
                    $originalSddl = (Get-CertificatePrivateKeySecurityDescriptor @capture).Sddl
                    Get-CertificatePrivateKeySecurityDescriptor @capture |
                        Backup-WindowsSecurityDescriptor `
                            -DestinationPath $backupPath `
                            -Confirm:$false
                    $json = Get-Content -LiteralPath $backupPath -Raw
                    $document = $json | ConvertFrom-Json

                    Add-CertificatePrivateKeyAccessRule @relocate `
                        -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false
                    $driftedSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl

                    Restore-WindowsSecurityDescriptor `
                        -BackupPath $backupPath `
                        -Confirm:$false `
                        -WarningAction SilentlyContinue
                    $restoredSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl

                    [pscustomobject]@{
                        SchemaVersion         = $document.SchemaVersion
                        RecordVersion         = $document.Records[0].RecordVersion
                        ObjectFamily          = $document.Records[0].ObjectFamily
                        RecordServer          = $document.Records[0].Server
                        RecordProviderName    = $document.Records[0].ProviderName
                        RecordKeyName         = $document.Records[0].KeyName
                        RecordKeyScope        = $document.Records[0].KeyScope
                        RecordThumbprint      = $document.Records[0].CertificateThumbprint
                        RecordCanonicalTarget = $document.Records[0].CanonicalTarget
                        CertificateThumbprint = $fixture.Certificate.Thumbprint.ToUpperInvariant()
                        ContainsKeyMaterial   = $json -match 'BEGIN [A-Z ]*PRIVATE KEY|RawData'
                        OriginalSddl          = $originalSddl
                        DriftedSddl           = $driftedSddl
                        RestoredSddl          = $restoredSddl
                        ComputerName          = $env:COMPUTERNAME
                    }
                }
                finally {
                    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
                }
            }

        $result.SchemaVersion | Should -Be 2
        $result.RecordVersion | Should -Be 2
        $result.ObjectFamily | Should -BeExactly 'CertificatePrivateKey'
        $result.RecordServer | Should -Be $result.ComputerName
        $result.RecordProviderName |
            Should -BeExactly 'Microsoft Software Key Storage Provider'
        $result.RecordKeyName | Should -Not -BeNullOrEmpty
        $result.RecordKeyScope | Should -BeExactly 'Machine'
        $result.RecordThumbprint | Should -BeExactly $result.CertificateThumbprint
        $result.RecordCanonicalTarget |
            Should -Match '^CertificatePrivateKey:Cng:Machine:[0-9A-F]{64}$'
        $result.ContainsKeyMaterial | Should -BeFalse
        $result.DriftedSddl | Should -Not -BeExactly $result.OriginalSddl
        $result.RestoredSddl | Should -BeExactly $result.OriginalSddl
    }

    It 'Should refuse to replay a private-key record on another computer' {
        $backupJson = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest, $script:resolveFixture.ToString() `
            -ScriptBlock {
                param($Manifest, $ResolveFixture)

                Import-Module $Manifest -Force -ErrorAction Stop
                $fixture = & ([scriptblock]::Create($ResolveFixture))
                $backupPath = Join-Path $env:TEMP (
                    'wac-key-backup-{0}.json' -f [guid]::NewGuid().ToString('N')
                )
                try {
                    Get-CertificatePrivateKeySecurityDescriptor `
                        -ProviderName $fixture.ProviderName `
                        -KeyName $fixture.KeyName `
                        -KeyScope Machine |
                        Backup-WindowsSecurityDescriptor `
                            -DestinationPath $backupPath `
                            -Confirm:$false
                    Get-Content -LiteralPath $backupPath -Raw
                }
                finally {
                    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
                }
            }

        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
        $localPath = Join-Path $env:TEMP (
            'wac-key-foreign-{0}.json' -f [guid]::NewGuid().ToString('N')
        )
        try {
            [IO.File]::WriteAllText($localPath, $backupJson)

            # This host is the management domain controller, so the record names
            # a different computer than the one replaying it.
            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $localPath `
                    -Confirm:$false `
                    -WarningAction SilentlyContinue
            } | Should -Throw '*captured on another computer*'
        }
        finally {
            Remove-Item -LiteralPath $localPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should refuse a restore while the key serves a critical binding' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest, $script:resolveFixture.ToString() `
            -ScriptBlock {
                param($Manifest, $ResolveFixture)

                Import-Module $Manifest -Force -ErrorAction Stop
                $fixture = & ([scriptblock]::Create($ResolveFixture))
                $relocate = @{
                    ProviderName = $fixture.ProviderName
                    KeyName      = $fixture.KeyName
                    KeyScope     = 'Machine'
                }
                $backupPath = Join-Path $env:TEMP (
                    'wac-key-backup-{0}.json' -f [guid]::NewGuid().ToString('N')
                )
                $netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
                $bindingPort = 48444
                $bindingApplicationId = '{6f1cbf6b-1c1a-4d1e-9d2e-4c1b4d3f5a21}'
                $originalSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl
                try {
                    Get-CertificatePrivateKeySecurityDescriptor @relocate |
                        Backup-WindowsSecurityDescriptor `
                            -DestinationPath $backupPath `
                            -Confirm:$false

                    # The record must differ from the live DACL, because an
                    # already-converged restore is a no-op that never reaches the
                    # binding gate.
                    Add-CertificatePrivateKeyAccessRule @relocate `
                        -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false

                    $boundRefusal = $null
                    try {
                        $null = & $netshPath http add sslcert `
                            "ipport=0.0.0.0:$bindingPort" `
                            "certhash=$($fixture.Certificate.Thumbprint)" `
                            "appid=$bindingApplicationId" `
                            'certstorename=MY' 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            throw "Unable to create the disposable HTTP.sys binding; netsh returned $LASTEXITCODE."
                        }
                        try {
                            Restore-WindowsSecurityDescriptor `
                                -BackupPath $backupPath `
                                -Confirm:$false `
                                -WarningAction SilentlyContinue `
                                -ErrorAction Stop
                        }
                        catch {
                            $boundRefusal = $_.Exception.Message
                        }
                    }
                    finally {
                        $null = & $netshPath http delete sslcert "ipport=0.0.0.0:$bindingPort" 2>&1
                    }
                    $boundSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl

                    Restore-WindowsSecurityDescriptor `
                        -BackupPath $backupPath `
                        -Confirm:$false `
                        -WarningAction SilentlyContinue
                    $releasedSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl

                    [pscustomobject]@{
                        OriginalSddl = $originalSddl
                        BoundRefusal = $boundRefusal
                        BoundSddl    = $boundSddl
                        ReleasedSddl = $releasedSddl
                    }
                }
                finally {
                    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
                }
            }

        $result.BoundRefusal | Should -BeLike '*serves a critical binding*'
        $result.BoundSddl | Should -Not -BeExactly $result.OriginalSddl
        $result.ReleasedSddl | Should -BeExactly $result.OriginalSddl
    }

    It 'Should converge the private-key descriptor and rule DSC resources' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest, $script:resolveFixture.ToString() `
            -ScriptBlock {
                param($Manifest, $ResolveFixture)

                Import-Module $Manifest -Force -ErrorAction Stop
                $module = Get-Module WindowsAccessControl
                $fixture = & ([scriptblock]::Create($ResolveFixture))
                $relocate = @{
                    ProviderName = $fixture.ProviderName
                    KeyName      = $fixture.KeyName
                    KeyScope     = 'Machine'
                }
                $originalSddl = (Get-CertificatePrivateKeySecurityDescriptor @relocate).Sddl
                try {
                    $ruleState = & $module {
                        param($ProviderName, $KeyName)

                        $resource = [WindowsAccessControlCertificatePrivateKeyAccessRule]::new()
                        $resource.ProviderName = $ProviderName
                        $resource.KeyName = $KeyName
                        $resource.KeyScope = 'Machine'
                        $resource.Account = 'BUILTIN\Users'
                        $resource.AccessRights = [WindowsCryptoKeyRights]::Read
                        $resource.AccessControlType =
                            [Security.AccessControl.AccessControlType]::Allow
                        $resource.Ensure = [WindowsAccessControlDscEnsure]::Present

                        $initial = $resource.Test()
                        $resource.Set()
                        $afterSet = $resource.Test()
                        $resource.Ensure = [WindowsAccessControlDscEnsure]::Absent
                        $resource.Set()
                        $afterRemove = $resource.Test()
                        [pscustomobject]@{
                            Initial     = $initial
                            AfterSet    = $afterSet
                            AfterRemove = $afterRemove
                        }
                    } $fixture.ProviderName $fixture.KeyName

                    # Drift the key so the descriptor resource has something to
                    # converge, then prove a repeated consistency pass stays
                    # green despite the generic bit the provider adds.
                    Add-CertificatePrivateKeyAccessRule @relocate `
                        -Account 'BUILTIN\Users' -AccessRights Read -Confirm:$false

                    $descriptorState = & $module {
                        param($ProviderName, $KeyName, $Sddl)

                        $resource =
                            [WindowsAccessControlCertificatePrivateKeySecurityDescriptor]::new()
                        $resource.ProviderName = $ProviderName
                        $resource.KeyName = $KeyName
                        $resource.KeyScope = 'Machine'
                        $resource.Sections = [WindowsSecurityDescriptorSection]::Access
                        $resource.Sddl = $Sddl

                        $drifted = $resource.Test()
                        $resource.Set()
                        $afterSet = $resource.Test()
                        $repeated = $resource.Test()
                        [pscustomobject]@{
                            Drifted  = $drifted
                            AfterSet = $afterSet
                            Repeated = $repeated
                            Reasons  = @($resource.Get().Reasons).Count
                        }
                    } $fixture.ProviderName $fixture.KeyName $originalSddl

                    $denyRefusal = $null
                    try {
                        & $module {
                            param($ProviderName, $KeyName)

                            $resource =
                                [WindowsAccessControlCertificatePrivateKeyAccessRule]::new()
                            $resource.ProviderName = $ProviderName
                            $resource.KeyName = $KeyName
                            $resource.KeyScope = 'Machine'
                            $resource.Account = 'Everyone'
                            $resource.AccessRights = [WindowsCryptoKeyRights]::Read
                            $resource.AccessControlType =
                                [Security.AccessControl.AccessControlType]::Deny
                            $resource.Ensure = [WindowsAccessControlDscEnsure]::Present
                            $resource.Set()
                        } $fixture.ProviderName $fixture.KeyName
                    }
                    catch {
                        $denyRefusal = $_.Exception.Message
                    }

                    [pscustomobject]@{
                        RuleInitial         = $ruleState.Initial
                        RuleAfterSet        = $ruleState.AfterSet
                        RuleAfterRemove     = $ruleState.AfterRemove
                        DescriptorDrifted   = $descriptorState.Drifted
                        DescriptorAfterSet  = $descriptorState.AfterSet
                        DescriptorRepeated  = $descriptorState.Repeated
                        DescriptorReasons   = $descriptorState.Reasons
                        DenyRefusal         = $denyRefusal
                        OriginalSddl        = $originalSddl
                        FinalSddl           = (
                            Get-CertificatePrivateKeySecurityDescriptor @relocate
                        ).Sddl
                    }
                }
                finally {
                    Set-CertificatePrivateKeySecurityDescriptor @relocate `
                        -Sddl $originalSddl -Confirm:$false
                }
            }

        $result.RuleInitial | Should -BeFalse
        $result.RuleAfterSet | Should -BeTrue
        $result.RuleAfterRemove | Should -BeTrue
        $result.DescriptorDrifted | Should -BeFalse
        $result.DescriptorAfterSet | Should -BeTrue
        $result.DescriptorRepeated | Should -BeTrue
        $result.DescriptorReasons | Should -Be 0
        $result.DenyRefusal | Should -BeLike '*deny rule cannot be created*'
        $result.FinalSddl | Should -BeExactly $result.OriginalSddl
    }
}

Describe 'Certificate private-key directory-service binding' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    BeforeAll {
        # This suite runs on the management domain controller, so the LDAPS
        # branch of the binding gate can be exercised where it applies.
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
        $script:localModule = Get-Module WindowsAccessControl
        $script:productType = (
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        ).ProductType
    }

    It 'Should reach the NTDS service store and refuse a certificate the directory can serve' {
        $script:productType | Should -Be 2 -Because 'this suite runs on a domain controller'

        # A service store is not reachable through StoreLocation. This proves the
        # native path completes on a domain controller; whether the store holds
        # the LDAPS certificate depends on how the certificate was enrolled, so
        # the count is reported rather than asserted.
        $ntdsCertificates = @(
            & $script:localModule {
                Get-WindowsServiceStoreCertificate -ServiceName 'NTDS' -StoreName 'MY'
            }
        )
        $myCertificates = @(
            & $script:localModule {
                Get-WindowsMachineStoreCertificate -StoreName 'My' -Required
            }
        )
        Write-Information (
            'NTDS\MY holds {0} certificates; LocalMachine\My holds {1}.' -f
            $ntdsCertificates.Count, $myCertificates.Count
        ) -InformationAction Continue
        ($ntdsCertificates.Count + $myCertificates.Count) |
            Should -BeGreaterThan 0 -Because 'a domain controller holds a certificate the directory can serve'

        $bindings = @(& $script:localModule { Get-WindowsBoundCertificateThumbprint })
        $directoryBindings = @(
            $bindings | Where-Object Binding -EQ 'DirectoryServices'
        )
        $directoryBindings | Should -Not -BeNullOrEmpty -Because 'a domain controller holds a server-authentication certificate'
        $directoryBindings[0].Detail |
            Should -Match "'(NTDS\\MY|My)'" -Because 'the reported binding must name the store it came from'

        try {
            $thumbprint = $directoryBindings[0].Thumbprint
            $certificate = @($ntdsCertificates + $myCertificates) |
                Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $thumbprint } |
                Select-Object -First 1
            $certificate | Should -Not -BeNullOrEmpty

            # The read-only command exposes the same detection the write gate
            # uses, so the refusal is proven without writing to a live directory
            # key.
            $reported = @(Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate)
            @($reported.Binding) | Should -Contain 'DirectoryServices'
        }
        finally {
            # Both producers hand the caller certificates it owns.
            foreach ($stored in @($ntdsCertificates + $myCertificates)) {
                $stored.Dispose()
            }
        }
    }
}

