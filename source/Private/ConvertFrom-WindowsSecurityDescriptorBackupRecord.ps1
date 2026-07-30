function ConvertFrom-WindowsSecurityDescriptorBackupRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$Record,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate
    )

    process {
        $recordVersion = 0
        $sections = 0
        if (-not [int]::TryParse([string]$Record.RecordVersion, [ref]$recordVersion) -or
            $recordVersion -notin @(1, 2) -or
            [string]::IsNullOrWhiteSpace([string]$Record.ObjectFamily) -or
            [string]::IsNullOrWhiteSpace([string]$Record.Target) -or
            [string]::IsNullOrWhiteSpace([string]$Record.CanonicalTarget) -or
            -not $Record.PSObject.Properties['Sddl'] -or
            $null -eq $Record.Sddl) {
            throw [System.IO.InvalidDataException]::new(
                'The backup contains an invalid security descriptor record.'
            )
        }
        if (-not [int]::TryParse([string]$Record.Sections, [ref]$sections) -or
            $sections -lt 1 -or $sections -gt 15) {
            throw [System.IO.InvalidDataException]::new(
                "The backup record for '$($Record.CanonicalTarget)' has invalid sections."
            )
        }
        # ADR 0016 keeps each object family pinned to exactly one record version
        # so an enterprise record can never be replayed as a local target and a
        # local record can never claim server authority it does not carry.
        $familyRecordVersion = switch ([string]$Record.ObjectFamily) {
            'FileSystem' { 1; break }
            'RegistryKey' { 1; break }
            'Service' { 1; break }
            'ServiceControlManager' { 1; break }
            'Process' { 1; break }
            'SmbShare' { 2; break }
            'ADObject' { 2; break }
            default {
                throw [System.IO.InvalidDataException]::new(
                    "The backup record contains unsupported object family '$($Record.ObjectFamily)'."
                )
            }
        }
        if ($recordVersion -ne $familyRecordVersion) {
            throw [System.IO.InvalidDataException]::new(
                "The backup record for '$($Record.CanonicalTarget)' must use record version $familyRecordVersion for object family '$($Record.ObjectFamily)'."
            )
        }
        if ([string]$Record.Integrity.Algorithm -cne 'SHA256' -or
            [string]$Record.Integrity.Digest -cnotmatch '^[0-9A-F]{64}$') {
            throw [System.IO.InvalidDataException]::new(
                'The backup record does not contain supported integrity metadata.'
            )
        }

        $actualHash = Get-WindowsSecurityDescriptorRecordHash -Record $Record
        $expectedHash = [byte[]]::new(32)
        for ($index = 0; $index -lt $expectedHash.Length; $index++) {
            $expectedHash[$index] = [Convert]::ToByte(
                ([string]$Record.Integrity.Digest).Substring($index * 2, 2),
                16
            )
        }
        $difference = 0
        for ($index = 0; $index -lt $expectedHash.Length; $index++) {
            $difference = $difference -bor ($expectedHash[$index] -bxor $actualHash[$index])
        }
        if ($difference -ne 0) {
            throw [System.Security.Cryptography.CryptographicException]::new(
                "Backup record integrity validation failed for '$($Record.CanonicalTarget)'."
            )
        }

        $hasSignatureMetadata = -not [string]::IsNullOrWhiteSpace(
            [string]$Record.Integrity.SignatureAlgorithm
        ) -or -not [string]::IsNullOrWhiteSpace(
            [string]$Record.Integrity.CertificateThumbprint
        ) -or -not [string]::IsNullOrWhiteSpace(
            [string]$Record.Integrity.Signature
        )
        if ($hasSignatureMetadata) {
            if (-not $VerificationCertificate) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The signed backup record requires a verification certificate.'
                )
            }
            if ([string]$Record.Integrity.SignatureAlgorithm -cne
                'RSASSA-PKCS1-v1_5-SHA256') {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The backup record uses an unsupported signature algorithm.'
                )
            }
            $expectedThumbprint = $VerificationCertificate.Thumbprint.Replace(
                ' ',
                ''
            ).ToUpperInvariant()
            if ([string]$Record.Integrity.CertificateThumbprint -cne
                $expectedThumbprint) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The backup record signing certificate does not match the verification certificate.'
                )
            }
            $now = [DateTime]::UtcNow
            if ($now -lt $VerificationCertificate.NotBefore.ToUniversalTime() -or
                $now -gt $VerificationCertificate.NotAfter.ToUniversalTime()) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The verification certificate is not currently valid.'
                )
            }
            try {
                $signature = [Convert]::FromBase64String(
                    [string]$Record.Integrity.Signature
                )
            } catch {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The backup record contains an invalid signature encoding.',
                    $_.Exception
                )
            }
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
                $VerificationCertificate
            )
            if (-not $rsa) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The verification certificate does not contain a supported RSA public key.'
                )
            }
            try {
                $signatureIsValid = $rsa.VerifyHash(
                    $actualHash,
                    $signature,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                )
            } finally {
                $rsa.Dispose()
            }
            if (-not $signatureIsValid) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    "Backup record signature validation failed for '$($Record.CanonicalTarget)'."
                )
            }
        } elseif ($VerificationCertificate) {
            throw [System.Security.Cryptography.CryptographicException]::new(
                'The verification certificate requires every backup record to be signed.'
            )
        }

        try {
            $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                [string]$Record.Sddl
            )
        } catch {
            throw [System.IO.InvalidDataException]::new(
                "The backup record for '$($Record.CanonicalTarget)' contains invalid SDDL.",
                $_.Exception
            )
        }
        $selectedSections = [WindowsSecurityDescriptorSection]$sections
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Owner) -ne 0 -and
            -not $rawDescriptor.Owner) {
            throw [System.IO.InvalidDataException]::new(
                'The backup record does not contain a selected owner.'
            )
        }
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Group) -ne 0 -and
            -not $rawDescriptor.Group) {
            throw [System.IO.InvalidDataException]::new(
                'The backup record does not contain a selected primary group.'
            )
        }
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Access) -ne 0 -and
            -not $rawDescriptor.DiscretionaryAcl) {
            throw [System.IO.InvalidDataException]::new(
                'The backup record does not contain a selected non-null DACL.'
            )
        }
        $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
            [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
            -not $systemAclPresent) {
            throw [System.IO.InvalidDataException]::new(
                'The backup record does not explicitly represent the selected SACL.'
            )
        }

        if ([string]$Record.ObjectFamily -eq 'FileSystem') {
            if ([string]$Record.ItemType -notin @('File', 'Directory')) {
                throw [System.IO.InvalidDataException]::new(
                    'A filesystem backup record requires File or Directory item type.'
                )
            }
            $fullPath = [System.IO.Path]::GetFullPath([string]$Record.Target)
            if (-not [string]::Equals(
                $fullPath,
                [string]$Record.CanonicalTarget,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                throw [System.IO.InvalidDataException]::new(
                    'The filesystem backup target does not match its canonical identity.'
                )
            }
        } elseif ([string]$Record.ObjectFamily -eq 'RegistryKey') {
            if ([string]$Record.RegistryView -notin @(
                'Default'
                'Registry32'
                'Registry64'
            )) {
                throw [System.IO.InvalidDataException]::new(
                    'A registry backup record requires a supported registry view.'
                )
            }
        } elseif ([string]$Record.ObjectFamily -eq 'Process') {
            $processId = 0
            $creationTimeFileTime = 0L
            if (-not [int]::TryParse([string]$Record.ProcessId, [ref]$processId) -or
                $processId -le 0 -or
                -not [long]::TryParse(
                    [string]$Record.CreationTimeFileTime,
                    [ref]$creationTimeFileTime
                ) -or
                $creationTimeFileTime -le 0 -or
                [string]$Record.CanonicalTarget -cne
                    "Process:$processId`:$creationTimeFileTime") {
                throw [System.IO.InvalidDataException]::new(
                    'A process backup record requires a matching PID and creation identity.'
                )
            }
        } elseif ([string]$Record.ObjectFamily -eq 'SmbShare') {
            if ($sections -ne [int][WindowsSecurityDescriptorSection]::Access) {
                throw [System.IO.InvalidDataException]::new(
                    'An SMB share backup record selects only the access section.'
                )
            }
            $shareServer = [string]$Record.Server
            $shareName = [string]$Record.ShareName
            if ([string]::IsNullOrWhiteSpace($shareServer) -or
                [string]::IsNullOrWhiteSpace($shareName) -or
                $shareName -cne [string]$Record.Target -or
                [string]$Record.CanonicalTarget -cne (
                    'SmbShare:{0}:{1}' -f $shareServer.ToUpperInvariant(),
                        $shareName.ToUpperInvariant())) {
                throw [System.IO.InvalidDataException]::new(
                    'An SMB share backup record requires a matching server and share identity.'
                )
            }
        } elseif ([string]$Record.ObjectFamily -eq 'ADObject') {
            if ($sections -ne [int][WindowsSecurityDescriptorSection]::Access) {
                throw [System.IO.InvalidDataException]::new(
                    'An Active Directory backup record selects only the access section.'
                )
            }
            $objectGuid = [guid]::Empty
            $directoryServer = [string]$Record.Server
            $distinguishedName = [string]$Record.DistinguishedName
            $domainNamingContext = [string]$Record.DomainNamingContext
            if ([string]::IsNullOrWhiteSpace($directoryServer) -or
                [string]::IsNullOrWhiteSpace($distinguishedName) -or
                [string]::IsNullOrWhiteSpace($domainNamingContext) -or
                $distinguishedName -cne [string]$Record.Target -or
                -not [guid]::TryParse([string]$Record.ObjectGuid, [ref]$objectGuid) -or
                $objectGuid -eq [guid]::Empty -or
                [string]$Record.CanonicalTarget -cne (
                    'ADObject:{0}:{1}' -f $directoryServer.ToUpperInvariant(),
                        $objectGuid.ToString('D').ToUpperInvariant())) {
                throw [System.IO.InvalidDataException]::new(
                    'An Active Directory backup record requires a matching server, distinguished name, domain, and object GUID.'
                )
            }
            if (-not (Test-WindowsADDistinguishedNameWithinBase `
                        -DistinguishedName $distinguishedName `
                        -BaseDistinguishedName $domainNamingContext)) {
                throw [System.IO.InvalidDataException]::new(
                    'An Active Directory backup record must name an object inside its recorded domain partition.'
                )
            }
        }

        [pscustomobject]@{
            RecordVersion         = $recordVersion
            ObjectFamily         = [string]$Record.ObjectFamily
            Target               = [string]$Record.Target
            CanonicalTarget      = [string]$Record.CanonicalTarget
            ItemType             = [string]$Record.ItemType
            RegistryView         = [string]$Record.RegistryView
            ProcessId            = if ([string]$Record.ObjectFamily -eq 'Process') {
                $processId
            } else {
                $null
            }
            CreationTimeFileTime = if ([string]$Record.ObjectFamily -eq 'Process') {
                $creationTimeFileTime
            } else {
                $null
            }
            Server               = if ($recordVersion -ge 2) {
                [string]$Record.Server
            } else {
                $null
            }
            ShareName            = if ([string]$Record.ObjectFamily -eq 'SmbShare') {
                [string]$Record.ShareName
            } else {
                $null
            }
            DistinguishedName    = if ([string]$Record.ObjectFamily -eq 'ADObject') {
                [string]$Record.DistinguishedName
            } else {
                $null
            }
            ObjectGuid           = if ([string]$Record.ObjectFamily -eq 'ADObject') {
                $objectGuid
            } else {
                $null
            }
            DomainNamingContext  = if ([string]$Record.ObjectFamily -eq 'ADObject') {
                [string]$Record.DomainNamingContext
            } else {
                $null
            }
            Sections             = [WindowsSecurityDescriptorSection]$sections
            Sddl                 = [string]$Record.Sddl
            Integrity            = $Record.Integrity
        }
    }
}
