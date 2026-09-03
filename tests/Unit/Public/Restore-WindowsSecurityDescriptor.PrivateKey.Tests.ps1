BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    $script:canonicalTarget =
        'CertificatePrivateKey:Cng:Machine:' + ('A1B2C3D4' * 8)
    $script:softwareProvider = 'Microsoft Software Key Storage Provider'
    $script:backupRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'WacPrivateKeyRestore-{0}' -f [guid]::NewGuid().ToString('N')
    )
    $null = New-Item -Path $script:backupRoot -ItemType Directory -Force

    function New-TestPrivateKeyBackup {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions',
            '',
            Justification = 'This Pester fixture only writes a disposable backup file.'
        )]
        param(
            [string]$Server = [Environment]::MachineName,
            [string]$ProviderName = 'Microsoft Software Key Storage Provider',
            [string]$KeyName = 'WacUnitKey',
            [string]$KeyScope = 'Machine',
            [string]$CanonicalTarget =
                ('CertificatePrivateKey:Cng:Machine:' + ('A1B2C3D4' * 8)),
            [string]$Sddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        )

        $descriptor = [pscustomobject]@{
            ObjectType            = 'CertificatePrivateKey'
            Path                  = '0123456789ABCDEF0123456789ABCDEF01234567'
            Server                = $Server
            ProviderName          = $ProviderName
            KeyName               = $KeyName
            KeyScope              = $KeyScope
            CertificateThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
            CanonicalTarget       = $CanonicalTarget
            Sections              = 4
            Sddl                  = $Sddl
        }
        $descriptor.PSObject.TypeNames.Insert(
            0, 'WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
        )
        $descriptor.PSObject.TypeNames.Add('WindowsAccessControl.SecurityDescriptor')

        $path = Join-Path $script:backupRoot ('{0}.json' -f [guid]::NewGuid().ToString('N'))
        $descriptor | Backup-WindowsSecurityDescriptor `
            -DestinationPath $path `
            -Confirm:$false
        $path
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:backupRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Certificate private-key restore routing' -Tag 'Unit', 'WindowsOnly' {
    It 'Should relocate the key by provider, key name, and key scope' {
        $backupPath = New-TestPrivateKeyBackup
        InModuleScope WindowsAccessControl -Parameters @{
            BackupPath      = $backupPath
            CanonicalTarget = $script:canonicalTarget
        } {
            Mock Get-CertificatePrivateKeySecurityDescriptor {
                [pscustomobject]@{
                    CanonicalTarget = $CanonicalTarget
                    Sddl            = 'D:P(A;;FA;;;SY)'
                }
            }
            Mock Set-CertificatePrivateKeySecurityDescriptor { }

            Restore-WindowsSecurityDescriptor `
                -BackupPath $BackupPath `
                -Confirm:$false `
                -WarningAction SilentlyContinue

            Should -Invoke Get-CertificatePrivateKeySecurityDescriptor `
                -Times 1 -Exactly -ParameterFilter {
                    $ProviderName -ceq 'Microsoft Software Key Storage Provider' -and
                    $KeyName -ceq 'WacUnitKey' -and
                    $KeyScope -ceq 'Machine'
                }
            Should -Invoke Set-CertificatePrivateKeySecurityDescriptor `
                -Times 1 -Exactly -ParameterFilter {
                    $ProviderName -ceq 'Microsoft Software Key Storage Provider' -and
                    $KeyName -ceq 'WacUnitKey' -and
                    $KeyScope -ceq 'Machine' -and
                    $Sddl -ceq 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' -and
                    $ExpectedCanonicalTarget -ceq $CanonicalTarget -and
                    -not $PSBoundParameters.ContainsKey('Certificate')
                }
        }
    }

    It 'Should reject a record replayed on another computer before opening the key' {
        $backupPath = New-TestPrivateKeyBackup -Server 'WACNOTTHISNODE'
        InModuleScope WindowsAccessControl -Parameters @{ BackupPath = $backupPath } {
            Mock Get-CertificatePrivateKeySecurityDescriptor { }
            Mock Set-CertificatePrivateKeySecurityDescriptor { }

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $BackupPath `
                    -Confirm:$false `
                    -WarningAction SilentlyContinue
            } | Should -Throw '*captured on another computer*'

            Should -Invoke Get-CertificatePrivateKeySecurityDescriptor -Times 0 -Exactly
            Should -Invoke Set-CertificatePrivateKeySecurityDescriptor -Times 0 -Exactly
        }
    }

    It 'Should reject a record whose key no longer has the recorded identity' {
        $backupPath = New-TestPrivateKeyBackup
        InModuleScope WindowsAccessControl -Parameters @{ BackupPath = $backupPath } {
            # A different container file name hashes to a different canonical
            # target, which is what a replay against another machine or another
            # key produces.
            Mock Get-CertificatePrivateKeySecurityDescriptor {
                [pscustomobject]@{
                    CanonicalTarget =
                        'CertificatePrivateKey:Cng:Machine:' + ('FFFFFFFF' * 8)
                    Sddl            = 'D:P(A;;FA;;;SY)'
                }
            }
            Mock Set-CertificatePrivateKeySecurityDescriptor { }

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $BackupPath `
                    -Confirm:$false `
                    -WarningAction SilentlyContinue
            } | Should -Throw '*does not match its canonical identity*'

            Should -Invoke Set-CertificatePrivateKeySecurityDescriptor -Times 0 -Exactly
        }
    }

    It 'Should refuse an unsupported provider before any key is opened' {
        # No mocks: the real target boundary rejects the provider allow-list
        # violation during preparation.
        $backupPath = New-TestPrivateKeyBackup `
            -ProviderName 'Microsoft Smart Card Key Storage Provider'

        {
            Restore-WindowsSecurityDescriptor `
                -BackupPath $backupPath `
                -Confirm:$false `
                -WarningAction SilentlyContinue
        } | Should -Throw '*not admitted*'
    }
}

Describe 'Certificate private-key restore write gates' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        # Every case drives the real write boundary: only the key resolution and
        # the provider read are replaced, so each specification 0015 gate runs
        # exactly as it does for a direct write.
        $script:storedSddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
    }

    It 'Should refuse a restore that <Case>' -ForEach @(
        @{
            Case      = 'adds a deny ACE'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Candidate = 'D:P(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)'
            Message   = '*adds a deny ACE*'
        }
        @{
            Case      = 'contains a conditional ACE'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Candidate = 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))(XA;;FA;;;BA;(@USER.Title=="x"))'
            Message   = '*Only plain allow and deny ACEs*'
        }
        @{
            Case      = 'drops the SYSTEM full-control grant'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Candidate = 'D:P(A;;FA;;;BA)(A;;0x120089;;;BU)'
            Message   = "*must grant full control to 'S-1-5-18'*"
        }
        @{
            Case      = 'drops the Administrators full-control grant'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Candidate = 'D:P(A;;FA;;;SY)(A;;0x120089;;;BU)'
            Message   = "*must grant full control to 'S-1-5-32-544'*"
        }
        @{
            Case      = 'removes an existing service grant'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;LS)'
            Candidate = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Message   = "*removes access that service identity 'S-1-5-19'*"
        }
        @{
            Case      = 'changes the stored DACL protection state'
            Stored    = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            Candidate = 'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'
            Message   = '*protection state does not match*'
        }
    ) {
        $backupPath = New-TestPrivateKeyBackup -Sddl $Candidate
        InModuleScope WindowsAccessControl -Parameters @{
            BackupPath      = $backupPath
            StoredSddl      = $Stored
            CanonicalTarget = $script:canonicalTarget
            Expected        = $Message
        } {
            $rsa = [Security.Cryptography.RSACng]::new(2048)
            try {
                $stored = [Security.AccessControl.RawSecurityDescriptor]::new($StoredSddl)
                $storedBytes = [byte[]]::new($stored.BinaryLength)
                $stored.GetBinaryForm($storedBytes, 0)

                Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                Mock Assert-WindowsCngKeyCriticalBinding { }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        ObjectType            = 'CertificatePrivateKey'
                        Path                  = $null
                        Server                = [Environment]::MachineName
                        ProviderName          = $ProviderName
                        KeyName               = $KeyName
                        UniqueName            = 'container-file-name'
                        KeyScope              = 'Machine'
                        CertificateThumbprint = $null
                        CanonicalTarget       = $CanonicalTarget
                        DescriptorSource      = 'CngKey'
                    }
                    & $Operation $target $rsa.Key @ArgumentList
                }

                {
                    Restore-WindowsSecurityDescriptor `
                        -BackupPath $BackupPath `
                        -Confirm:$false `
                        -WarningAction SilentlyContinue
                } | Should -Throw $Expected
            }
            finally {
                $rsa.Dispose()
            }
        }
    }

    It 'Should refuse a restore of a key that serves a critical binding' {
        $backupPath = New-TestPrivateKeyBackup `
            -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'
        InModuleScope WindowsAccessControl -Parameters @{
            BackupPath      = $backupPath
            StoredSddl      = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            CanonicalTarget = $script:canonicalTarget
        } {
            $rsa = [Security.Cryptography.RSACng]::new(2048)
            try {
                # A certificate over the same key is what a real binding names.
                # The gate reads the target public key from the key itself, so no
                # certificate reaches the write boundary.
                $bound = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=WacUnitBoundKey',
                    $rsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1
                ).CreateSelfSigned(
                    [datetimeoffset]::UtcNow.AddMinutes(-5),
                    [datetimeoffset]::UtcNow.AddMinutes(5))
                try {
                    $stored = [Security.AccessControl.RawSecurityDescriptor]::new($StoredSddl)
                    $storedBytes = [byte[]]::new($stored.BinaryLength)
                    $stored.GetBinaryForm($storedBytes, 0)

                    Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                    Mock Get-WindowsMachineCertificateStoreName { 'MY' }
                    Mock Get-WindowsMachineStoreCertificate { }
                    Mock Get-WindowsServiceStoreCertificate {
                        [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                            $bound.RawData
                        )
                    }
                    Mock Get-WindowsBoundCertificateThumbprint {
                        [pscustomobject]@{
                            Binding    = 'HttpSys'
                            Thumbprint = $bound.Thumbprint.ToUpperInvariant()
                            Detail     = '0.0.0.0:443'
                        }
                    }
                    Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                        $target = [pscustomobject]@{
                            ObjectType      = 'CertificatePrivateKey'
                            Server          = [Environment]::MachineName
                            ProviderName    = $ProviderName
                            KeyName         = $KeyName
                            KeyScope        = 'Machine'
                            CanonicalTarget = $CanonicalTarget
                        }
                        & $Operation $target $rsa.Key @ArgumentList
                    }

                    {
                        Restore-WindowsSecurityDescriptor `
                            -BackupPath $BackupPath `
                            -Confirm:$false `
                            -WarningAction SilentlyContinue
                    } | Should -Throw '*serves a critical binding*'
                }
                finally {
                    $bound.Dispose()
                }
            }
            finally {
                $rsa.Dispose()
            }
        }
    }

    It 'Should reassert a converged DACL without reaching the provider' {
        $backupPath = New-TestPrivateKeyBackup -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        InModuleScope WindowsAccessControl -Parameters @{
            BackupPath      = $backupPath
            CanonicalTarget = $script:canonicalTarget
        } {
            $rsa = [Security.Cryptography.RSACng]::new(2048)
            try {
                $stored = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
                )
                $storedBytes = [byte[]]::new($stored.BinaryLength)
                $stored.GetBinaryForm($storedBytes, 0)

                Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                Mock Assert-WindowsCngKeyCriticalBinding { }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        ObjectType      = 'CertificatePrivateKey'
                        Server          = [Environment]::MachineName
                        ProviderName    = $ProviderName
                        KeyName         = $KeyName
                        KeyScope        = 'Machine'
                        CanonicalTarget = $CanonicalTarget
                    }
                    & $Operation $target $rsa.Key @ArgumentList
                }

                {
                    Restore-WindowsSecurityDescriptor `
                        -BackupPath $BackupPath `
                        -Confirm:$false `
                        -WarningAction SilentlyContinue
                } | Should -Not -Throw

                Should -Invoke Assert-WindowsCngKeyCriticalBinding -Times 0 -Exactly
            }
            finally {
                $rsa.Dispose()
            }
        }
    }
}
