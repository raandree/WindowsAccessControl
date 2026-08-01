BeforeAll {
    $script:labModulePath = Join-Path -Path $PSScriptRoot -ChildPath (
        '..\..\Lab\WindowsAccessControl.DomainLab.psm1'
    )
    Import-Module -Name $script:labModulePath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl.DomainLab' -Force -ErrorAction SilentlyContinue
}

Describe 'WindowsAccessControl domain lab plan' -Tag 'Unit', 'WindowsOnly' {
    It 'Should expose deterministic disposable resource identities without secrets' {
        $plan = Get-WindowsAccessControlDomainLabPlan `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test'

        $plan.Domain.RootOrganizationalUnit |
            Should -BeExactly 'OU=WindowsAccessControlLab,DC=example,DC=test'
        $plan.Domain.OrganizationalUnits.Name |
            Should -Be @('Identities', 'Groups', 'Targets')
        $plan.Domain.Users.SamAccountName |
            Should -Be @('WacLabOperator', 'WacLabUser', 'WacLabDenied', 'WacLabService')
        $plan.Domain.Groups.SamAccountName |
            Should -Be @('WacLabReaders', 'WacLabNested')
        $plan.MemberServer.ComputerName |
            Should -BeExactly 'member01.example.test'
        $plan.MemberServer.ShareName | Should -BeExactly 'WacLab$'
        $plan.MemberServer.TaskFolder | Should -BeExactly '\WindowsAccessControlLab'
        $plan.MemberServer.CertificateSubject |
            Should -BeExactly 'CN=WindowsAccessControl Lab Key'
        $plan.PSObject.Properties.Name | Should -Not -Contain 'Credential'
        $plan.PSObject.Properties.Name | Should -Not -Contain 'Password'
    }

    It 'Should export the domain-lab lifecycle commands' {
        $exportedCommands = (Get-Command -Module 'WindowsAccessControl.DomainLab').Name

        $exportedCommands | Should -Contain 'Initialize-WindowsAccessControlDomainLab'
        $exportedCommands | Should -Contain 'Test-WindowsAccessControlDomainLab'
        $exportedCommands | Should -Contain 'Remove-WindowsAccessControlDomainLab'
        $exportedCommands | Should -Contain 'Invoke-WindowsAccessControlDomainLabAcceptance'
    }

    It 'Should not invoke either mutation boundary under WhatIf' {
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlDomainFixture
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlMemberFixture

        Initialize-WindowsAccessControlDomainLab `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test' `
            -WhatIf

        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlDomainFixture -Times 0
        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlMemberFixture -Times 0
    }

    It 'Should compensate both boundaries when member-server setup fails' {
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlDomainFixture `
            -MockWith { [pscustomobject]@{ Boundary = 'DomainController' } }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Initialize-WindowsAccessControlMemberFixture `
            -MockWith { throw 'Expected member-server setup failure.' }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Remove-WindowsAccessControlMemberFixture
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Remove-WindowsAccessControlDomainFixture

        {
            Initialize-WindowsAccessControlDomainLab `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*Expected member-server setup failure*'

        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Remove-WindowsAccessControlMemberFixture -Times 1
        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            -CommandName Remove-WindowsAccessControlDomainFixture -Times 1
    }

    It 'Should treat the marked root plus nine marked descendants as complete' {
        $plan = Get-WindowsAccessControlDomainLabPlan `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test'
        $root = [pscustomobject]@{ Description = $plan.Marker }
        $objects = @(
            1..10 | ForEach-Object {
                [pscustomobject]@{ Description = $plan.Marker }
            }
        )

        $result = InModuleScope `
            -ModuleName 'WindowsAccessControl.DomainLab' `
            -Parameters @{ TestPlan = $plan; TestRoot = $root; TestObjects = $objects } `
            -ScriptBlock {
                Test-WindowsAccessControlDomainLabObjectSet `
                    -Plan $TestPlan `
                    -Root $TestRoot `
                    -Objects $TestObjects `
                    -RecoveryIdentityReady $true
            }

        $result.ExpectedObjectCount | Should -Be 10
        $result.ObjectCount | Should -Be 10
        $result.MarkedObjectCount | Should -Be 10
        $result.Ready | Should -BeTrue
    }

    It 'Should run every fixed suite and retain a redacted cleanup ledger' {
        $outputPath = Join-Path $TestDrive 'domain-lab-acceptance.json'
        Set-Content -LiteralPath $outputPath -Value 'stale evidence'
        $script:invokedPaths = [Collections.Generic.List[string]]::new()
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            param($Path)
            $script:invokedPaths.Add([IO.Path]::GetFileName($Path))
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 2
                PassedCount = 2
                FailedCount = 0
                SkippedCount = 0
                Duration = [timespan]::FromSeconds(1)
                Tests = @()
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }

        $previousMember = $env:WAC_DOMAIN_LAB_MEMBER
        $result = Invoke-WindowsAccessControlDomainLabAcceptance `
            -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test' `
            -OutputPath $outputPath `
            -Confirm:$false

        $script:invokedPaths | Should -Be @(
            'WindowsAccessControl.DomainLab.Live.Tests.ps1'
            'CertificatePrivateKeyPermissions.Live.Tests.ps1'
            'TaskSchedulerPermissions.Live.Tests.ps1'
            'SmbSharePermissions.Live.Tests.ps1'
            'ADObjectPermissions.Live.Tests.ps1'
            'ADObjectReplication.Live.Tests.ps1'
        )
        $result.Result | Should -BeExactly 'Passed'
        $result.Suites | Should -HaveCount 6
        $result.CleanupLedger | Should -HaveCount 6
        $result.CleanupLedger.Ready | Should -Not -Contain $false
        $result.Suites.StartedAtUtc | Should -Not -Contain $null
        $result.Suites.CompletedAtUtc | Should -Not -Contain $null
        $result.PSObject.Properties.Name | Should -Not -Contain 'MemberServer'
        $result.PSObject.Properties.Name | Should -Not -Contain 'DomainDistinguishedName'
        $env:WAC_DOMAIN_LAB_MEMBER | Should -BeExactly $previousMember
        $retained = Get-Content -LiteralPath $outputPath -Raw
        $retained | Should -Not -Match 'stale evidence'
        $retained | Should -Not -Match 'member01|DC=example'
        $retained | Should -Match 'SuiteEphemeralRuntime'
    }

    It 'Should not run Pester or write evidence under WhatIf' {
        $outputPath = Join-Path $TestDrive 'domain-lab-whatif.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester

        Invoke-WindowsAccessControlDomainLabAcceptance `
            -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test' `
            -OutputPath $outputPath `
            -WhatIf

        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            Invoke-Pester -Times 0 -Exactly
        $outputPath | Should -Not -Exist
    }

    It 'Should retain exact skip reasons without infrastructure identifiers' {
        $outputPath = Join-Path $TestDrive 'domain-lab-skip.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 2
                PassedCount = 1
                FailedCount = 0
                SkippedCount = 1
                Duration = [timespan]::FromSeconds(1)
                Tests = @(
                    [pscustomobject]@{
                        Result = 'Skipped'
                        ExpandedName = 'Should require a missing capability'
                        ErrorRecord = [pscustomobject]@{
                            Exception = [InvalidOperationException]::new(
                                'Required capability on member01.example.test for DC=example,DC=test at \\member01.example.test\WacLab$ with S-1-5-18 and 0123456789abcdef0123456789abcdef01234567 is unavailable.'
                            )
                        }
                    }
                )
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }

        {
            Invoke-WindowsAccessControlDomainLabAcceptance `
                -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -OutputPath $outputPath `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*reported 1 skipped test*'

        $summary = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        $summary.Result | Should -BeExactly 'Failed'
        $summary.Suites[0].SkipReasons[0].Test |
            Should -BeExactly 'Should require a missing capability'
        $summary.Suites[0].SkipReasons[0].Reason |
            Should -Match '^Required capability.*is unavailable\.$'
        $retained = Get-Content -LiteralPath $outputPath -Raw
        $retained | Should -Not -Match (
            'member01|DC=example|S-1-5-18|0123456789abcdef|\\\\member01'
        )
    }

    It 'Should reject a Pester-passed suite when every test is skipped' {
        $outputPath = Join-Path $TestDrive 'domain-lab-all-skipped.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 1
                PassedCount = 0
                FailedCount = 0
                SkippedCount = 1
                Duration = [timespan]::FromSeconds(1)
                Tests = @(
                    [pscustomobject]@{
                        Result = 'Skipped'
                        ExpandedName = 'Should require one capability'
                        ErrorRecord = [pscustomobject]@{
                            Exception = [InvalidOperationException]::new(
                                'Capability unavailable.'
                            )
                        }
                    }
                )
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }

        {
            Invoke-WindowsAccessControlDomainLabAcceptance `
                -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -OutputPath $outputPath `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*executed no passing tests*'

        (Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json).Result |
            Should -BeExactly 'Failed'
    }

    It 'Should reject a Pester-passed suite that discovers zero tests' {
        $outputPath = Join-Path $TestDrive 'domain-lab-zero-tests.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 0
                PassedCount = 0
                FailedCount = 0
                SkippedCount = 0
                Duration = [timespan]::Zero
                Tests = @()
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }

        {
            Invoke-WindowsAccessControlDomainLabAcceptance `
                -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -OutputPath $outputPath `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*executed no passing tests*'

        (Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json).Result |
            Should -BeExactly 'Failed'
    }

    It 'Should stop after a suite leaves the lab unready and retain failed evidence' {
        $outputPath = Join-Path $TestDrive 'domain-lab-failed.json'
        $script:statusCall = 0
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 1
                PassedCount = 1
                FailedCount = 0
                SkippedCount = 0
                Duration = [timespan]::FromSeconds(1)
                Tests = @()
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                $script:statusCall++
                [pscustomobject]@{
                    Ready = $script:statusCall -lt 2
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{
                        Ready = $script:statusCall -lt 2
                    }
                }
            }

        {
            Invoke-WindowsAccessControlDomainLabAcceptance `
                -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -OutputPath $outputPath `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*left the disposable lab unready*'

        $summary = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        $summary.Result | Should -BeExactly 'Failed'
        $summary.CleanupLedger[-1].Ready | Should -BeFalse
        Should -Invoke -ModuleName 'WindowsAccessControl.DomainLab' `
            Invoke-Pester -Times 2 -Exactly
    }

    It 'Should retain its evidence writer when a nested suite reloads the harness module' {
        $outputPath = Join-Path $TestDrive 'domain-lab-reload.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            Remove-Item `
                Function:Write-WindowsAccessControlDomainLabAcceptanceEvidence `
                -Force `
                -ErrorAction SilentlyContinue
            Remove-Item `
                Function:Test-WindowsAccessControlDomainFixture `
                -Force `
                -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Result = 'Passed'
                TotalCount = 1
                PassedCount = 1
                FailedCount = 0
                SkippedCount = 0
                Duration = [timespan]::FromSeconds(1)
                Tests = @()
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }

        $result = Invoke-WindowsAccessControlDomainLabAcceptance `
            -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
            -DomainDistinguishedName 'DC=example,DC=test' `
            -MemberServer 'member01.example.test' `
            -OutputPath $outputPath `
            -Confirm:$false

        $result.Result | Should -BeExactly 'Passed'
        $outputPath | Should -Exist
        InModuleScope 'WindowsAccessControl.DomainLab' {
            Get-Command `
                -Name Test-WindowsAccessControlDomainFixture `
                -CommandType Function `
                -ErrorAction Stop |
                Should -Not -BeNullOrEmpty
        }
    }

    It 'Should preserve the primary suite failure when evidence finalization also fails' {
        $outputPath = Join-Path `
            $TestDrive `
            'missing-evidence-directory\domain-lab-primary-error.json'
        Mock -ModuleName 'WindowsAccessControl.DomainLab' Invoke-Pester {
            [pscustomobject]@{
                Result = 'Failed'
                TotalCount = 1
                PassedCount = 0
                FailedCount = 1
                SkippedCount = 0
                Duration = [timespan]::FromSeconds(1)
                Tests = @()
            }
        }
        Mock -ModuleName 'WindowsAccessControl.DomainLab' `
            Test-WindowsAccessControlDomainLab {
                [pscustomobject]@{
                    Ready = $true
                    DomainController = [pscustomobject]@{ Ready = $true }
                    MemberServer = [pscustomobject]@{ Ready = $true }
                }
            }
        $caught = $null
        try {
            Invoke-WindowsAccessControlDomainLabAcceptance `
                -RepositoryRoot (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')) `
                -DomainDistinguishedName 'DC=example,DC=test' `
                -MemberServer 'member01.example.test' `
                -OutputPath $outputPath `
                -Confirm:$false
        }
        catch {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception | Should -BeOfType [AggregateException]
        $caught.Exception.Message |
            Should -Match "Suite 'WindowsAccessControl.DomainLab.Live.Tests.ps1' completed with result 'Failed'"
        (@($caught.Exception.InnerExceptions.Message) -join ' ') |
            Should -Match 'acceptance evidence directory does not exist'
        $outputPath | Should -Not -Exist
    }
}
