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
}
