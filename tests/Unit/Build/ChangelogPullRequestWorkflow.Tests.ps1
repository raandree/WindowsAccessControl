BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    Import-Module -Name powershell-yaml -ErrorAction Stop
    $script:workflow = Get-Content (Join-Path $script:repositoryRoot '.github/workflows/build.yml') -Raw |
        ConvertFrom-Yaml

    $script:publishStep = @($script:workflow.jobs.publish.steps)
    $script:sendStepName = 'Send changelog pull request'
    $script:verifyStepName = 'Verify the changelog pull request exists'
    $script:verifyStep = @(
        $script:publishStep | Where-Object -FilterScript { $_.name -eq $script:verifyStepName }
    )

    # Kept separate so that a missing step reads as an unmet expectation in each
    # test below instead of an index error.
    $script:verifyStepDefinition = $script:verifyStep | Select-Object -First 1
}

Describe 'Changelog pull request verification' {
    <#
        Sampler's Create_ChangeLog_GitHub_PR wraps everything after it creates the
        changelog branch in a try/catch that only writes the error to the build
        log, and Invoke-Build still exits zero. The v0.2.0 release pushed
        'updateChangelogAfterv0.2.0', opened no pull request, and reported the
        step as successful. The publish job therefore asks GitHub itself.
    #>
    It 'Should verify the pull request in the publish job' {
        $script:verifyStep | Should -HaveCount 1 -Because (
            "the publish job must carry a step named '{0}'" -f $script:verifyStepName
        )

        $script:verifyStepDefinition.shell | Should -Be 'pwsh'
    }

    It 'Should verify after the task that opens the pull request' {
        $stepName = @($script:publishStep | ForEach-Object -Process { $_.name })
        $sendIndex = [System.Array]::IndexOf($stepName, $script:sendStepName)
        $verifyIndex = [System.Array]::IndexOf($stepName, $script:verifyStepName)

        $sendIndex | Should -BeGreaterOrEqual 0 -Because (
            "the release still runs '{0}'" -f $script:sendStepName
        )

        $verifyIndex | Should -BeGreaterThan $sendIndex -Because (
            'the pull request can only be verified once the task has run'
        )
    }

    It 'Should ask the GitHub API for the pull request of the changelog branch' {
        $runScript = $script:verifyStepDefinition.run

        $runScript | Should -Match '/pulls\?' -Because (
            'the pull request list of that branch is the evidence'
        )

        $runScript | Should -Match 'state=all' -Because (
            'a pull request that was opened and closed again still counts'
        )

        $runScript | Should -Match '\bthrow\b' -Because (
            'a missing pull request must end the release instead of passing'
        )
    }

    It 'Should read the API with the release token, for the branch of this tag' {
        $script:verifyStepDefinition.env.Keys | Should -Contain 'GitHubToken'

        $script:verifyStepDefinition.env.GitHubToken | Should -Match 'secrets\.GitHubToken' -Because (
            'the publish job already holds that secret'
        )

        $script:verifyStepDefinition.env.ChangelogBranch | Should -Match '^updateChangelogAfter' -Because (
            'Sampler names the changelog branch after the released tag'
        )

        $script:verifyStepDefinition.env.ChangelogBranch | Should -Match 'github\.ref_name' -Because (
            'the released tag is the one this run published'
        )
    }

    <#
        A build of main publishes a pre-release, and UpdateChangelogOnPrerelease
        is false in build.yaml, so the task returns before it creates a branch.
        Only a stable release tag owes a changelog pull request.
    #>
    It 'Should expect a pull request only for a release tag' {
        $script:verifyStepDefinition.'if' | Should -Match 'refs/tags/' -Because (
            'a pre-release build of main creates no changelog branch'
        )
    }

    <#
        This step is the release's only guard against a pull request that was
        never opened, so its own logic is exercised and not just its text. GitHub
        answers a head filter that matches nothing with an empty JSON array,
        which Invoke-RestMethod writes as a single unenumerated object: counting
        it with '@(Invoke-RestMethod ...)' yields one, and the guard would then
        confirm a pull request that does not exist.
    #>
    Context 'When the verification script runs' {
        BeforeAll {
            $env:Repository = 'owner/repository'
            $env:RepositoryOwner = 'owner'
            $env:ChangelogBranch = 'updateChangelogAfterv9.9.9'
            $env:GitHubToken = 'token-used-only-by-the-mock'
        }

        AfterAll {
            Remove-Item -Path Env:\Repository, Env:\RepositoryOwner, Env:\ChangelogBranch,
                Env:\GitHubToken -ErrorAction SilentlyContinue
        }

        It 'Should end the release when the API reports no pull request' {
            $script:verifyStepDefinition.run | Should -Not -BeNullOrEmpty

            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -match '/pulls\?' } -MockWith {
                # The comma keeps the empty array unenumerated, which is how
                # Invoke-RestMethod hands back an empty JSON array.
                , @()
            }

            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -match '/branches/' } -MockWith {
                [pscustomobject] @{ name = $env:ChangelogBranch }
            }

            $verificationScript = [scriptblock]::Create([string] $script:verifyStepDefinition.run)

            { & $verificationScript } |
                Should -Throw -ExpectedMessage "*No pull request exists from 'updateChangelogAfterv9.9.9'*"
        }

        It 'Should pass the release when the API reports a pull request' {
            $script:verifyStepDefinition.run | Should -Not -BeNullOrEmpty

            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -match '/pulls\?' } -MockWith {
                [pscustomobject] @{ number = 42; state = 'open' }
            }

            $verificationScript = [scriptblock]::Create([string] $script:verifyStepDefinition.run)

            { & $verificationScript } | Should -Not -Throw
        }
    }
}
