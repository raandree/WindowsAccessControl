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

    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAccessControl.DomainLab.psm1'
    Import-Module -Name $modulePath -Force -ErrorAction Stop
    Import-Module -Name ActiveDirectory -ErrorAction Stop
    $script:domainDistinguishedName = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $script:memberServer = $env:WAC_DOMAIN_LAB_MEMBER
    $script:plan = Get-WindowsAccessControlDomainLabPlan `
        -DomainDistinguishedName $script:domainDistinguishedName `
        -MemberServer $script:memberServer
}

AfterAll {
    $null = Initialize-WindowsAccessControlDomainLab `
        -DomainDistinguishedName $script:domainDistinguishedName `
        -MemberServer $script:memberServer `
        -Confirm:$false
}

Describe 'WindowsAccessControl disposable domain lab' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should initialize every fixture idempotently' {
        $first = Initialize-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false
        $second = Initialize-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false
        $status = Test-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer

        $first.DomainController.CreatedCount | Should -Be 0
        $first.MemberServer.CreatedCount | Should -Be 0
        $second.DomainController.CreatedCount | Should -Be 0
        $second.MemberServer.CreatedCount | Should -Be 0
        $status.Ready | Should -BeTrue
    }

    It 'Should repair a managed certificate whose CNG key is missing' {
        $null = Initialize-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false
        $null = Invoke-Command `
            -ComputerName $script:memberServer `
            -Authentication Kerberos `
            -ArgumentList $script:plan.MemberServer `
            -ErrorAction Stop `
            -ScriptBlock {
                param($MemberPlan)

                $certificates = @(
                    Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                        Where-Object {
                            $_.Subject -ceq $MemberPlan.CertificateSubject -and
                            $_.FriendlyName -ceq $MemberPlan.CertificateName
                        }
                )
                if ($certificates.Count -ne 1) {
                    throw "Expected one managed certificate, found $($certificates.Count)."
                }
                $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                    GetRSAPrivateKey($certificates[0])
                try {
                    $privateKey.Key.Delete()
                }
                finally {
                    $privateKey.Dispose()
                }
            }

        try {
            $repair = Initialize-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer `
                -Confirm:$false
            $status = Test-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer

            $repair.MemberServer.CreatedResources | Should -Contain 'MemberCertificateKey'
            $status.MemberServer.CertificateReady | Should -BeTrue
        }
        finally {
            $null = Remove-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer `
                -Confirm:$false
            $null = Initialize-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer `
                -Confirm:$false
        }
    }

    It 'Should repair a missing certificate whose managed CNG key remains' {
        $null = Initialize-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false
        $keyRemains = Invoke-Command `
            -ComputerName $script:memberServer `
            -Authentication Kerberos `
            -ArgumentList $script:plan.MemberServer `
            -ErrorAction Stop `
            -ScriptBlock {
                param($MemberPlan)

                $certificates = @(
                    Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                        Where-Object {
                            $_.Subject -ceq $MemberPlan.CertificateSubject -and
                            $_.FriendlyName -ceq $MemberPlan.CertificateName
                        }
                )
                if ($certificates.Count -ne 1) {
                    throw "Expected one managed certificate, found $($certificates.Count)."
                }
                Remove-Item -LiteralPath $certificates[0].PSPath -Force -ErrorAction Stop
                [Security.Cryptography.CngKey]::Exists(
                    $MemberPlan.CertificateKeyName,
                    [Security.Cryptography.CngProvider]::new(
                        $MemberPlan.CertificateProvider
                    ),
                    [Security.Cryptography.CngKeyOpenOptions]::MachineKey
                )
            }
        $repairJob = Start-Job `
            -ArgumentList $modulePath, $script:domainDistinguishedName, $script:memberServer `
            -ScriptBlock {
                param($ModulePath, $DomainDistinguishedName, $MemberServer)

                Import-Module -Name $ModulePath -Force -ErrorAction Stop
                Initialize-WindowsAccessControlDomainLab `
                    -DomainDistinguishedName $DomainDistinguishedName `
                    -MemberServer $MemberServer `
                    -Confirm:$false
            }

        try {
            $completedJob = Wait-Job -Job $repairJob -Timeout 30
            $completedJob | Should -Not -BeNullOrEmpty
            $repair = Receive-Job -Job $repairJob -ErrorAction Stop
            $status = Test-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer

            $keyRemains | Should -BeTrue
            $repair.MemberServer.CreatedResources | Should -Contain 'MemberCertificateKey'
            $status.MemberServer.CertificateReady | Should -BeTrue
        }
        finally {
            Stop-Job -Job $repairJob -ErrorAction SilentlyContinue
            Remove-Job -Job $repairJob -Force -ErrorAction SilentlyContinue
            $null = Remove-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer `
                -Confirm:$false
            $null = Initialize-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $script:domainDistinguishedName `
                -MemberServer $script:memberServer `
                -Confirm:$false
        }
    }

    It 'Should remove every fixture and its CNG key idempotently' {
        $keyIdentity = Invoke-Command `
            -ComputerName $script:memberServer `
            -Authentication Kerberos `
            -ArgumentList $script:plan.MemberServer `
            -ErrorAction Stop `
            -ScriptBlock {
                param($MemberPlan)

                $certificates = @(
                    Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                        Where-Object {
                            $_.Subject -ceq $MemberPlan.CertificateSubject -and
                            $_.FriendlyName -ceq $MemberPlan.CertificateName
                        }
                )
                if ($certificates.Count -ne 1) {
                    throw "Expected one managed certificate, found $($certificates.Count)."
                }
                $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                    GetRSAPrivateKey($certificates[0])
                try {
                    [pscustomobject]@{
                        UniqueName = $privateKey.Key.UniqueName
                        Provider   = $privateKey.Key.Provider.Provider
                    }
                }
                finally {
                    $privateKey.Dispose()
                }
            }

        $first = Remove-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false
        $keyStillOpen = Invoke-Command `
            -ComputerName $script:memberServer `
            -Authentication Kerberos `
            -ArgumentList $keyIdentity.UniqueName, $keyIdentity.Provider `
            -ErrorAction Stop `
            -ScriptBlock {
                param($UniqueName, $Provider)

                try {
                    $providerObject = [Security.Cryptography.CngProvider]::new($Provider)
                    $key = [Security.Cryptography.CngKey]::Open(
                        $UniqueName,
                        $providerObject,
                        [Security.Cryptography.CngKeyOpenOptions]::MachineKey
                    )
                    try {
                        $true
                    }
                    finally {
                        $key.Dispose()
                    }
                }
                catch [Security.Cryptography.CryptographicException] {
                    $false
                }
            }
        $second = Remove-WindowsAccessControlDomainLab `
            -DomainDistinguishedName $script:domainDistinguishedName `
            -MemberServer $script:memberServer `
            -Confirm:$false

        $first.DomainController.Removed | Should -BeTrue
        $first.MemberServer.Removed | Should -BeTrue
        $keyStillOpen | Should -BeFalse
        $second.DomainController.AlreadyAbsent | Should -BeTrue
        $second.MemberServer.AlreadyAbsent | Should -BeTrue
    }
}

Describe 'WindowsAccessControl module under test' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should load the module from the root this acceptance selected' {
        $root = & (Join-Path $PSScriptRoot 'Resolve-WindowsAccessControlLabModuleRoot.ps1')
        Import-Module -Name (Join-Path $root 'WindowsAccessControl.psd1') -Force -ErrorAction Stop
        try {
            $loaded = Get-Module WindowsAccessControl

            $loaded | Should -Not -BeNullOrEmpty
            $loaded.Path | Should -BeLike "$root*" `
                -Because 'every suite must load the same module this run selected'
        }
        finally {
            Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should reach an installed module root by name as well as by path' {
        $root = & (Join-Path $PSScriptRoot 'Resolve-WindowsAccessControlLabModuleRoot.ps1')
        $installedRoot = $env:WAC_LAB_MODULE_ROOT
        $available = @(
            Get-Module -ListAvailable -Name WindowsAccessControl |
                Where-Object { $_.Path -like "$root*" }
        )

        if ([string]::IsNullOrWhiteSpace($installedRoot)) {
            # A build-output run is deliberately not on PSModulePath, so the
            # only claim it can make is that no installed copy was selected.
            $root | Should -BeLike '*output*module*WindowsAccessControl*' `
                -Because 'without WAC_LAB_MODULE_ROOT the suites must load the build output'
        }
        else {
            $available.Count | Should -BeGreaterThan 0 `
                -Because 'an installed-package run must resolve the module by name from PSModulePath'
        }
    }
}

