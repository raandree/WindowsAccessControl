BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl

    function script:ConvertTo-DescriptorBinaryForm {
        param([string]$Sddl)

        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        , $bytes
    }

    function script:ConvertTo-Descriptor {
        param([string]$Sddl)

        [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    }

    $script:baselineSddl = 'D:P(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)'
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Certificate private-key rights normalization' -Tag 'Unit', 'WindowsOnly' {
    It 'Should expand every generic bit through the file generic mapping' {
        $cases = @(
            @{ Mask = 0x00120089L; Expected = 0x00120089L }
            @{ Mask = 0x80120089L; Expected = 0x00120089L }
            @{ Mask = 0x80000000L; Expected = 0x00120089L }
            @{ Mask = 0x40000000L; Expected = 0x00120116L }
            @{ Mask = 0x10000000L; Expected = 0x001F01FFL }
            @{ Mask = 0xD01F01FFL; Expected = 0x001F01FFL }
        )
        foreach ($case in $cases) {
            $actual = & $script:module {
                param($Mask)
                ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask $Mask
            } $case.Mask
            $actual | Should -Be $case.Expected -Because "mask 0x$('{0:X8}' -f $case.Mask) must expand deterministically"
        }
    }

    It 'Should treat a stored generic form and its requested form as the same DACL' {
        $requested = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        $stored = script:ConvertTo-Descriptor $script:baselineSddl

        $result = & $script:module {
            param($Left, $Right)
            Test-WindowsCngKeyDaclEquivalent -Left $Left -Right $Right
        } $requested $stored

        $result | Should -BeTrue
    }

    It 'Should compare the DACL as an unordered multiset' {
        $forward = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'
        $reversed = script:ConvertTo-Descriptor 'D:P(A;;0x120089;;;BU)(A;;FA;;;BA)(A;;FA;;;SY)'

        $result = & $script:module {
            param($Left, $Right)
            Test-WindowsCngKeyDaclEquivalent -Left $Left -Right $Right
        } $forward $reversed

        $result | Should -BeTrue
    }

    It 'Should report a different protection state as not equivalent' {
        $protected = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        $unprotected = script:ConvertTo-Descriptor 'D:(A;;FA;;;SY)(A;;FA;;;BA)'

        $result = & $script:module {
            param($Left, $Right)
            Test-WindowsCngKeyDaclEquivalent -Left $Left -Right $Right
        } $protected $unprotected

        $result | Should -BeFalse
    }
}

Describe 'Certificate private-key protected ACE gate' -Tag 'Unit', 'WindowsOnly' {
    It 'Should allow a candidate that keeps SYSTEM and Administrators full control' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeTrue
    }

    It 'Should reject a candidate that drops the SYSTEM grant' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(A;;FA;;;BA)'

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeFalse
        $result.Reason | Should -BeLike '*S-1-5-18*'
    }

    It 'Should reject a candidate that reduces Administrators below full control' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;0x120089;;;BA)'

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeFalse
        $result.Reason | Should -BeLike '*S-1-5-32-544*'
    }

    It 'Should reject a candidate that denies Administrators' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(D;;0x120089;;;BA)(A;;FA;;;SY)(A;;FA;;;BA)'

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeFalse
        $result.Reason | Should -BeLike '*must not deny*'
    }

    It 'Should reject a candidate that removes an existing service grant' {
        $current = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;NS)'
        $candidate = script:ConvertTo-Descriptor $script:baselineSddl

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeFalse
        $result.Reason | Should -BeLike '*service identity*'
    }

    It 'Should allow removing a grant that does not belong to a service identity' {
        $current = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'
        $candidate = script:ConvertTo-Descriptor $script:baselineSddl

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeTrue
    }

    It 'Should classify only real service identities as protected' {
        $cases = @(
            @{ Sid = 'S-1-5-19'; Expected = $true }
            @{ Sid = 'S-1-5-20'; Expected = $true }
            @{ Sid = 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'; Expected = $true }
            @{ Sid = 'S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415'; Expected = $true }
            @{ Sid = 'S-1-5-18'; Expected = $false }
            @{ Sid = 'S-1-5-32-544'; Expected = $false }
            @{ Sid = 'S-1-5-21-1-2-3-1001'; Expected = $false }
        )
        foreach ($case in $cases) {
            $actual = & $script:module {
                param($Sid)
                Test-WindowsCngKeyServiceIdentity -SecurityIdentifier $Sid
            } $case.Sid
            $actual | Should -Be $case.Expected -Because "SID $($case.Sid) must classify deterministically"
        }
    }
}

Describe 'Certificate private-key rule mutation' -Tag 'Unit', 'WindowsOnly' {
    It 'Should append an allow ACE and stay idempotent for the same effective rights' {
        $current = script:ConvertTo-DescriptorBinaryForm $script:baselineSddl
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $first = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Add `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L
        } $current $users
        $second = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Add `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L
        } $first $users

        $firstSddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($first, 0)).GetSddlForm('Access')
        $secondSddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($second, 0)).GetSddlForm('Access')

        $firstSddl | Should -BeLike '*BU*'
        $secondSddl | Should -BeExactly $firstSddl
    }

    It 'Should treat a stored generic mask as the same rule when adding' {
        $stored = script:ConvertTo-DescriptorBinaryForm 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x80120089;;;BU)'
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $result = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Add `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L
        } $stored $users

        $resultSddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($result, 0)).GetSddlForm('Access')
        $resultSddl | Should -BeExactly ([System.Security.AccessControl.RawSecurityDescriptor]::new($stored, 0)).GetSddlForm('Access')
    }

    It 'Should insert a deny ACE before every allow ACE' {
        $current = script:ConvertTo-DescriptorBinaryForm $script:baselineSddl
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $result = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Add `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L `
                -AccessControlType ([System.Security.AccessControl.AccessControlType]::Deny)
        } $current $users

        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($result, 0)
        $descriptor.DiscretionaryAcl[0].AceType | Should -Be ([System.Security.AccessControl.AceType]::AccessDenied)
    }

    It 'Should remove a stored generic ACE that matches the requested effective rights' {
        $stored = script:ConvertTo-DescriptorBinaryForm 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x80120089;;;BU)'
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $result = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Remove `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L
        } $stored $users

        $resultSddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($result, 0)).GetSddlForm('Access')
        $resultSddl | Should -Not -BeLike '*BU*'
    }

    It 'Should leave a rule with different rights in place during exact removal' {
        $stored = script:ConvertTo-DescriptorBinaryForm 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)'
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $result = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Remove `
                -SecurityIdentifier $Sid -AccessMask 0x00120089L
        } $stored $users

        $resultSddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($result, 0)).GetSddlForm('Access')
        $resultSddl | Should -BeLike '*BU*'
    }

    It 'Should reject a null DACL' {
        {
            & $script:module {
                param($Sid)
                $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BA')
                $bytes = [byte[]]::new($descriptor.BinaryLength)
                $descriptor.GetBinaryForm($bytes, 0)
                Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $bytes -Operation Add `
                    -SecurityIdentifier $Sid -AccessMask 0x00120089L
            } ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
        } | Should -Throw -ExpectedMessage '*non-null access ACL*'
    }
}

Describe 'Certificate private-key provider gate' -Tag 'Unit', 'WindowsOnly' {
    It 'Should report the Microsoft software key storage provider as software only' {
        $implementation = & $script:module {
            Get-WindowsCngProviderImplementation -ProviderName 'Microsoft Software Key Storage Provider'
        }

        $implementation.IsSoftware | Should -BeTrue
        $implementation.IsHardware | Should -BeFalse
        $implementation.IsSoftwareOnly | Should -BeTrue
    }

    It 'Should reject a provider that is not the supported software provider' {
        {
            & $script:module {
                Assert-WindowsCngKeyProviderSupport -ProviderName 'Microsoft Smart Card Key Storage Provider'
            }
        } | Should -Throw -ExpectedMessage '*not admitted*'
    }

    It 'Should treat a provider that reports a hardware flag as unsupported' {
        $implementation = & $script:module {
            Get-WindowsCngProviderImplementation -ProviderName 'Microsoft Smart Card Key Storage Provider'
        }

        $implementation.IsHardware | Should -BeTrue
        $implementation.IsSoftwareOnly | Should -BeFalse
    }

    It 'Should reject every legacy CAPI cryptographic service provider name' {
        $capiProviders = @(
            'Microsoft Enhanced Cryptographic Provider v1.0'
            'Microsoft Base Cryptographic Provider v1.0'
            'Microsoft Strong Cryptographic Provider'
            'Microsoft Enhanced RSA and AES Cryptographic Provider'
        )
        foreach ($providerName in $capiProviders) {
            {
                & $script:module {
                    param($ProviderName)
                    Assert-WindowsCngKeyProviderSupport -ProviderName $ProviderName
                } $providerName
            } | Should -Throw -ExpectedMessage '*not admitted*' -Because (
                "$providerName is a legacy CAPI provider that ADR 0024 refuses"
            )
        }
    }

    It 'Should reject a provider name that differs only by case' {
        {
            & $script:module {
                Assert-WindowsCngKeyProviderSupport -ProviderName 'microsoft software key storage provider'
            }
        } | Should -Throw -ExpectedMessage '*not admitted*'
    }
}

Describe 'Certificate private-key ACE support gate' -Tag 'Unit', 'WindowsOnly' {
    It 'Should reject a candidate that adds a deny ACE naming a containing group' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)'

        {
            & $script:module {
                param($Current, $Candidate)
                Assert-WindowsCngKeyAceSupport -CurrentDescriptor $Current -CandidateDescriptor $Candidate
            } $current $candidate
        } | Should -Throw -ExpectedMessage '*adds a deny ACE*'
    }

    It 'Should accept a deny ACE that already exists on the key' {
        $current = script:ConvertTo-Descriptor 'D:P(D;;0x120089;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)'
        $candidate = script:ConvertTo-Descriptor 'D:P(D;;0x120089;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;NS)'

        {
            & $script:module {
                param($Current, $Candidate)
                Assert-WindowsCngKeyAceSupport -CurrentDescriptor $Current -CandidateDescriptor $Candidate
            } $current $candidate
        } | Should -Not -Throw
    }

    It 'Should reject a conditional allow ACE that could grant nothing at evaluation time' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))(XA;;FA;;;BA;(@USER.Title=="x"))'

        {
            & $script:module {
                param($Current, $Candidate)
                Assert-WindowsCngKeyAceSupport -CurrentDescriptor $Current -CandidateDescriptor $Candidate
            } $current $candidate
        } | Should -Throw -ExpectedMessage '*Only plain allow and deny ACEs*'
    }

    It 'Should not let a conditional allow ACE satisfy the recovery grant' {
        $current = script:ConvertTo-Descriptor $script:baselineSddl
        $candidate = script:ConvertTo-Descriptor 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))(XA;;FA;;;BA;(@USER.Title=="x"))'

        $result = & $script:module {
            param($Current, $Candidate)
            Test-WindowsCngKeyProtectedAce -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate

        $result.IsAllowed | Should -BeFalse
    }

    It 'Should treat a conditional ACE and its plain equivalent as different DACLs' {
        $plain = script:ConvertTo-Descriptor 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        $conditional = script:ConvertTo-Descriptor 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))(XA;;FA;;;BA;(@USER.Title=="x"))'

        $result = & $script:module {
            param($Left, $Right)
            Test-WindowsCngKeyDaclEquivalent -Left $Left -Right $Right
        } $plain $conditional

        $result | Should -BeFalse
    }

    It 'Should treat two conditional ACEs with different conditions as different DACLs' {
        $first = script:ConvertTo-Descriptor 'D:P(XA;;FA;;;SY;(@USER.Title=="x"))'
        $second = script:ConvertTo-Descriptor 'D:P(XA;;FA;;;SY;(@USER.Title=="y"))'

        $result = & $script:module {
            param($Left, $Right)
            Test-WindowsCngKeyDaclEquivalent -Left $Left -Right $Right
        } $first $second

        $result | Should -BeFalse
    }
}

Describe 'Certificate private-key generic rights' -Tag 'Unit', 'WindowsOnly' {
    It 'Should stage a generic right whose mask exceeds a signed integer' {
        $current = script:ConvertTo-DescriptorBinaryForm $script:baselineSddl
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

        $result = & $script:module {
            param($Bytes, $Sid)
            Invoke-WindowsCngKeyAclRuleMutation -SecurityDescriptor $Bytes -Operation Add `
                -SecurityIdentifier $Sid -AccessMask ([long][WindowsCryptoKeyRights]::GenericRead -band 0xFFFFFFFFL)
        } $current $users

        $sddl = ([System.Security.AccessControl.RawSecurityDescriptor]::new($result, 0)).GetSddlForm('Access')
        $sddl | Should -BeLike '*BU*'
    }
}

Describe 'Certificate private-key binding identity' -Tag 'Unit', 'WindowsOnly' {
    It 'Should treat two certificates over the same key material as the same private key' {
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $first = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WacUnitFirst',
                $key,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            ).CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddMinutes(5))
            $renewed = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WacUnitRenewed',
                $key,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            ).CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-4), [datetimeoffset]::UtcNow.AddMinutes(6))
            $other = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WacUnitOther',
                [System.Security.Cryptography.RSA]::Create(2048),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            ).CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddMinutes(5))

            try {
                $sameKey = & $script:module {
                    param($Left, $Right)
                    Test-WindowsCertificateSharesPrivateKey -Left $Left -Right $Right
                } $first $renewed
                $differentKey = & $script:module {
                    param($Left, $Right)
                    Test-WindowsCertificateSharesPrivateKey -Left $Left -Right $Right
                } $first $other

                $first.Thumbprint | Should -Not -BeExactly $renewed.Thumbprint
                $sameKey | Should -BeTrue -Because 'renewal with key reuse must not bypass the binding gate'
                $differentKey | Should -BeFalse
            }
            finally {
                $first.Dispose()
                $renewed.Dispose()
                $other.Dispose()
            }
        }
        finally {
            $key.Dispose()
        }
    }
}

Describe 'Certificate server-authentication classification' -Tag 'Unit', 'WindowsOnly' {
    It 'Should treat a certificate without an enhanced key usage as server capable' {
        $certificate = & $script:module {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WacUnitNoEku',
                [System.Security.Cryptography.RSA]::Create(2048),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddMinutes(5))
        }
        try {
            $result = & $script:module {
                param($Certificate)
                Test-WindowsCertificateServerAuthentication -Certificate $Certificate
            } $certificate

            $result | Should -BeTrue
        }
        finally {
            $certificate.Dispose()
        }
    }

    It 'Should reject a certificate whose enhanced key usage excludes server authentication' {
        $certificate = & $script:module {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WacUnitClientEku',
                [System.Security.Cryptography.RSA]::Create(2048),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $usages = [System.Security.Cryptography.OidCollection]::new()
            $null = $usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $true))
            $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddMinutes(5))
        }
        try {
            $result = & $script:module {
                param($Certificate)
                Test-WindowsCertificateServerAuthentication -Certificate $Certificate
            } $certificate

            $result | Should -BeFalse
        }
        finally {
            $certificate.Dispose()
        }
    }
}
