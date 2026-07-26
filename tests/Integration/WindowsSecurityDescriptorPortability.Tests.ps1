BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    $registryTestRoot = 'HKCU:\Software\WindowsAccessControlPortabilityTest'
    if (Test-Path -LiteralPath $registryTestRoot -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $registryTestRoot).Count -eq 0) {
            Remove-Item -LiteralPath $registryTestRoot -Force `
                -ErrorAction SilentlyContinue
        }
    }
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Unified security descriptor backup' -Tag 'Integration', 'WindowsOnly' {
    It 'Should write one SHA-256 protected filesystem descriptor record' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'portable.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'portable.json'
        Set-Content -LiteralPath $testFile -Value 'portable'

        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access
        $record = $descriptor |
            Backup-WindowsSecurityDescriptor `
                -DestinationPath $backupPath `
                -PassThru

        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $backup.SchemaVersion | Should -Be 1
        $backup.Records | Should -HaveCount 1
        $backup.Records[0].ObjectFamily | Should -Be 'FileSystem'
        $backup.Records[0].CanonicalTarget |
            Should -Be ([System.IO.Path]::GetFullPath($testFile))
        $backup.Records[0].Sections | Should -Be 4
        $backup.Records[0].Sddl | Should -Not -BeNullOrEmpty
        $backup.Records[0].Integrity.Algorithm | Should -Be 'SHA256'
        $backup.Records[0].Integrity.Digest | Should -Match '^[0-9A-F]{64}$'
        $record.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.SecurityDescriptorBackupRecord'
    }

    It 'Should preserve registry service SCM and process target identity' {
        $testId = [guid]::NewGuid().ToString('N')
        $registryPath = "HKCU:\Software\WindowsAccessControlPortabilityTest\$testId"
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'cross-family.json'
        $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        try {
            $descriptors = @(
                Get-RegistryKeySecurityDescriptor -Path $registryPath -Sections Access
                Get-ServiceSecurityDescriptor -Name 'EventLog' -Sections Access
                Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access
                Get-ProcessSecurityDescriptor -ProcessId $PID -Sections Access
            )

            $records = @($descriptors |
                Backup-WindowsSecurityDescriptor `
                    -DestinationPath $backupPath `
                    -PassThru)
        } finally {
            Remove-Item -LiteralPath $registryPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }

        $records | Should -HaveCount 4
        $records.ObjectFamily | Should -Be @(
            'RegistryKey'
            'Service'
            'ServiceControlManager'
            'Process'
        )
        $records[0].RegistryView | Should -Be 'Default'
        $records[0].CanonicalTarget | Should -Match '^RegistryKey:Default:'
        $records[1].Target | Should -Be 'EventLog'
        $records[2].CanonicalTarget | Should -Be 'ServiceControlManager:Local'
        $records[3].ProcessId | Should -Be $PID
        $records[3].CreationTimeFileTime | Should -BeGreaterThan 0
        $records.Integrity.Digest |
            ForEach-Object { $_ | Should -Match '^[0-9A-F]{64}$' }
    }

    It 'Should reject duplicate canonical targets before writing' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'duplicate-target.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'duplicate-target.json'
        Set-Content -LiteralPath $testFile -Value 'duplicate'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access

        {
            @($descriptor, $descriptor) |
                Backup-WindowsSecurityDescriptor -DestinationPath $backupPath
        } | Should -Throw -ExpectedMessage '*duplicate*'
        $backupPath | Should -Not -Exist
    }

    It 'Should not access a signing private key under WhatIf' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'signing-whatif.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'signing-whatif.json'
        Set-Content -LiteralPath $testFile -Value 'whatif'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access

        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=WindowsAccessControl WhatIf signing test',
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        $publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $certificate.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
            )
        )
        try {
            {
                $descriptor | Backup-WindowsSecurityDescriptor `
                    -DestinationPath $backupPath `
                    -SigningCertificate $publicCertificate `
                    -WhatIf
            } | Should -Not -Throw
            $backupPath | Should -Not -Exist
        } finally {
            $publicCertificate.Dispose()
            $certificate.Dispose()
            $rsa.Dispose()
        }
    }

    It 'Should back up and restore an absent registry SACL' {
        $testId = [guid]::NewGuid().ToString('N')
        $registryPath = "HKCU:\Software\WindowsAccessControlPortabilityTest\$testId"
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'absent-sacl.json'
        $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        try {
            $before = Get-RegistryKeySecurityDescriptor `
                -Path $registryPath `
                -Sections Audit
            $before.NativeDescriptor.SystemAcl | Should -BeNullOrEmpty

            $before | Backup-WindowsSecurityDescriptor `
                -DestinationPath $backupPath
            Add-RegistryKeyAuditRule -Path $registryPath `
                -Account 'S-1-1-0' `
                -AccessRights QueryValues `
                -AuditFlags Failure `
                -Confirm:$false

            Restore-WindowsSecurityDescriptor `
                -BackupPath $backupPath `
                -Confirm:$false

            $after = Get-RegistryKeySecurityDescriptor `
                -Path $registryPath `
                -Sections Audit
            $after.NativeDescriptor.SystemAcl | Should -BeNullOrEmpty
            Get-RegistryKeyAuditRule -Path $registryPath -ExcludeInherited |
                Should -BeNullOrEmpty
        } finally {
            Remove-Item -LiteralPath $registryPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }

    It 'Should reject a selected SACL that is not explicitly represented' {
        $testId = [guid]::NewGuid().ToString('N')
        $registryPath = "HKCU:\Software\WindowsAccessControlPortabilityTest\$testId"
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'missing-sacl.json'
        $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        try {
            $descriptor = Get-RegistryKeySecurityDescriptor `
                -Path $registryPath `
                -Sections Audit
            $descriptor.Sddl = 'D:(A;;KR;;;WD)'

            {
                $descriptor | Backup-WindowsSecurityDescriptor `
                    -DestinationPath $backupPath
            } | Should -Throw -ExpectedMessage '*explicitly represent*selected SACL*'
            $backupPath | Should -Not -Exist
        } finally {
            Remove-Item -LiteralPath $registryPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Unified security descriptor restore' -Tag 'Integration', 'WindowsOnly' {
    It 'Should restore a verified filesystem descriptor record' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'restore-portable.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'restore-portable.json'
        Set-Content -LiteralPath $testFile -Value 'restore'
        Add-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -AccessRights Read
        Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Backup-WindowsSecurityDescriptor -DestinationPath $backupPath
        Get-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        Restore-WindowsSecurityDescriptor `
            -BackupPath $backupPath `
            -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Should -HaveCount 1
    }

    It 'Should verify every digest before restoring the first target' {
        $firstFile = Join-Path -Path $TestDrive -ChildPath 'digest-first.txt'
        $secondFile = Join-Path -Path $TestDrive -ChildPath 'digest-second.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'digest-tampered.json'
        Set-Content -LiteralPath $firstFile -Value 'first'
        Set-Content -LiteralPath $secondFile -Value 'second'
        Add-NTFSAccessRule -LiteralPath $firstFile `
            -Account 'S-1-1-0' `
            -AccessRights Read
        Add-NTFSAccessRule -LiteralPath $secondFile `
            -Account 'S-1-1-0' `
            -AccessRights Read
        Get-NTFSItemSecurityDescriptor `
            -LiteralPath $firstFile, $secondFile `
            -Sections Access |
            Backup-WindowsSecurityDescriptor -DestinationPath $backupPath
        Get-NTFSAccessRule `
            -LiteralPath $firstFile, $secondFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $backup.Records[1].Integrity.Digest = '0' * 64
        $backup | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $backupPath -Encoding utf8

        {
            Restore-WindowsSecurityDescriptor `
                -BackupPath $backupPath `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*integrity*'
        Get-NTFSAccessRule -LiteralPath $firstFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should restore registry service SCM and pinned process records' {
        $testId = [guid]::NewGuid().ToString('N')
        $registryPath = "HKCU:\Software\WindowsAccessControlPortabilityTest\$testId"
        $serviceName = "WacPortability$testId"
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'restore-families.json'
        $powershellPath = Join-Path $env:SystemRoot (
            'System32\WindowsPowerShell\v1.0\powershell.exe'
        )
        $process = $null
        $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        try {
            $binaryPath = "$env:SystemRoot\System32\cmd.exe /c exit 0"
            $serviceOutput = & sc.exe create $serviceName `
                'binPath=' $binaryPath `
                'start=' 'demand' 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Disposable service creation failed: $serviceOutput"
            }
            $process = Start-Process -FilePath $powershellPath `
                -ArgumentList '-NoProfile', '-NonInteractive', '-Command', `
                    '$null = ''WacPortabilityProcess''; Start-Sleep -Seconds 120' `
                -WindowStyle Hidden `
                -PassThru
            $null = $process.StartTime

            Add-RegistryKeyAccessRule -Path $registryPath `
                -Account 'S-1-1-0' `
                -AccessRights QueryValues `
                -Confirm:$false
            Add-ServiceAccessRule -Name $serviceName `
                -Account 'S-1-1-0' `
                -ServiceRights QueryStatus `
                -Confirm:$false
            $process | Add-ProcessAccessRule `
                -Account 'S-1-1-0' `
                -ProcessRights QueryInformation `
                -Confirm:$false

            @(
                Get-RegistryKeySecurityDescriptor -Path $registryPath -Sections Access
                Get-ServiceSecurityDescriptor -Name $serviceName -Sections Access
                Get-ServiceSecurityDescriptor -ServiceControlManager -Sections Access
                $process | Get-ProcessSecurityDescriptor -Sections Access
            ) | Backup-WindowsSecurityDescriptor -DestinationPath $backupPath

            Get-RegistryKeyAccessRule -Path $registryPath `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Remove-RegistryKeyAccessRule -Confirm:$false
            Get-ServiceAccessRule -Name $serviceName `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Remove-ServiceAccessRule -Confirm:$false
            $process | Get-ProcessAccessRule `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Remove-ProcessAccessRule -Confirm:$false

            $restored = @(Restore-WindowsSecurityDescriptor `
                -BackupPath $backupPath `
                -Confirm:$false `
                -PassThru)

            $restored | Should -HaveCount 4
            Get-RegistryKeyAccessRule -Path $registryPath `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Should -HaveCount 1
            Get-ServiceAccessRule -Name $serviceName `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Should -HaveCount 1
            $process | Get-ProcessAccessRule `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Should -HaveCount 1
        } finally {
            if ($process) {
                try {
                    if (-not $process.HasExited) {
                        $process.Kill()
                        $process.WaitForExit()
                    }
                } finally {
                    $process.Dispose()
                }
            }
            & sc.exe delete $serviceName 2>&1 | Out-Null
            Remove-Item -LiteralPath $registryPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }

    It 'Should require and verify the signing certificate before restore' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'signed-restore.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'signed-restore.json'
        Set-Content -LiteralPath $testFile -Value 'signed'
        Add-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -AccessRights Read

        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=WindowsAccessControl portability test',
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        try {
            Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
                Backup-WindowsSecurityDescriptor `
                    -DestinationPath $backupPath `
                    -SigningCertificate $certificate

            $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
            $backup.Records[0].Integrity.SignatureAlgorithm |
                Should -Be 'RSASSA-PKCS1-v1_5-SHA256'
            $backup.Records[0].Integrity.CertificateThumbprint |
                Should -Be $certificate.Thumbprint
            $backup.Records[0].Integrity.Signature |
                Should -Not -BeNullOrEmpty

            Get-NTFSAccessRule -LiteralPath $testFile `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Remove-NTFSAccessRule -Confirm:$false

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $backupPath `
                    -Confirm:$false
            } | Should -Throw -ExpectedMessage '*verification certificate*'
            Restore-WindowsSecurityDescriptor `
                -BackupPath $backupPath `
                -VerificationCertificate $certificate `
                -Confirm:$false

            Get-NTFSAccessRule -LiteralPath $testFile `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Should -HaveCount 1
        } finally {
            $certificate.Dispose()
            $rsa.Dispose()
        }
    }

    It 'Should reject changed signed content with a recomputed digest' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'signed-tamper.txt'
        $signedPath = Join-Path -Path $TestDrive -ChildPath 'signed-tamper.json'
        $changedPath = Join-Path -Path $TestDrive -ChildPath 'changed-content.json'
        Set-Content -LiteralPath $testFile -Value 'signed tamper'
        Add-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -AccessRights Read

        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=WindowsAccessControl signature tamper test',
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        try {
            Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
                Backup-WindowsSecurityDescriptor `
                    -DestinationPath $signedPath `
                    -SigningCertificate $certificate

            Add-NTFSAccessRule -LiteralPath $testFile `
                -Account 'S-1-5-32-545' `
                -AccessRights Write
            $currentDescriptor = Get-NTFSItemSecurityDescriptor `
                -LiteralPath $testFile `
                -Sections Access
            $currentDescriptor |
                Backup-WindowsSecurityDescriptor -DestinationPath $changedPath

            $signedBackup = Get-Content -LiteralPath $signedPath -Raw |
                ConvertFrom-Json
            $changedBackup = Get-Content -LiteralPath $changedPath -Raw |
                ConvertFrom-Json
            $signedBackup.Records[0].Sddl = $changedBackup.Records[0].Sddl
            $signedBackup.Records[0].Integrity.Digest =
                $changedBackup.Records[0].Integrity.Digest
            $signedBackup | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath $signedPath -Encoding utf8

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $signedPath `
                    -VerificationCertificate $certificate `
                    -Confirm:$false
            } | Should -Throw -ExpectedMessage '*signature validation failed*'
            (Get-NTFSItemSecurityDescriptor `
                -LiteralPath $testFile `
                -Sections Access).Sddl |
                Should -BeExactly $currentDescriptor.Sddl
        } finally {
            $certificate.Dispose()
            $rsa.Dispose()
        }
    }

    It 'Should reject mixed signed and unsigned records before restoring' {
        $firstFile = Join-Path -Path $TestDrive -ChildPath 'mixed-first.txt'
        $secondFile = Join-Path -Path $TestDrive -ChildPath 'mixed-second.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'mixed-signatures.json'
        Set-Content -LiteralPath $firstFile -Value 'first'
        Set-Content -LiteralPath $secondFile -Value 'second'
        Add-NTFSAccessRule -LiteralPath $firstFile `
            -Account 'S-1-1-0' `
            -AccessRights Read
        Add-NTFSAccessRule -LiteralPath $secondFile `
            -Account 'S-1-1-0' `
            -AccessRights Read

        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=WindowsAccessControl mixed signature test',
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        try {
            Get-NTFSItemSecurityDescriptor `
                -LiteralPath $firstFile, $secondFile `
                -Sections Access |
                Backup-WindowsSecurityDescriptor `
                    -DestinationPath $backupPath `
                    -SigningCertificate $certificate
            Get-NTFSAccessRule `
                -LiteralPath $firstFile, $secondFile `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Remove-NTFSAccessRule -Confirm:$false

            $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
            $backup.Records[1].Integrity.SignatureAlgorithm = $null
            $backup.Records[1].Integrity.CertificateThumbprint = $null
            $backup.Records[1].Integrity.Signature = $null
            $backup | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath $backupPath -Encoding utf8

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $backupPath `
                    -VerificationCertificate $certificate `
                    -Confirm:$false
            } | Should -Throw -ExpectedMessage '*every backup record to be signed*'
            Get-NTFSAccessRule -LiteralPath $firstFile `
                -Account 'S-1-1-0' `
                -ExcludeInherited |
                Should -BeNullOrEmpty
        } finally {
            $certificate.Dispose()
            $rsa.Dispose()
        }
    }

    It 'Should reject non-filesystem records through the NTFS restore command' {
        $testId = [guid]::NewGuid().ToString('N')
        $registryPath = "HKCU:\Software\WindowsAccessControlPortabilityTest\$testId"
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'ntfs-family-guard.json'
        $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        try {
            Get-RegistryKeySecurityDescriptor -Path $registryPath -Sections Access |
                Backup-WindowsSecurityDescriptor -DestinationPath $backupPath

            {
                Restore-NTFSItemSecurityDescriptor `
                    -BackupPath $backupPath `
                    -Confirm:$false
            } | Should -Throw -ExpectedMessage '*only filesystem backup records*'
        } finally {
            Remove-Item -LiteralPath $registryPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
}
