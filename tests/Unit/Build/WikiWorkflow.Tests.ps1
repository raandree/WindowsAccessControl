BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    Import-Module -Name powershell-yaml -ErrorAction Stop
    $script:workflow = Get-Content (Join-Path $script:repositoryRoot '.github/workflows/build.yml') -Raw |
        ConvertFrom-Yaml
    $script:buildConfiguration = Get-Content (Join-Path $script:repositoryRoot 'build.yaml') -Raw |
        ConvertFrom-Yaml
}

Describe 'Standard wiki publishing workflow' {
    It 'Should publish on Ubuntu with the standard DSC Community tasks' {
        $script:workflow.jobs.publish.'runs-on' | Should -Be 'ubuntu-latest'
        $publishStep = @($script:workflow.jobs.publish.steps | Where-Object {
            $_.name -eq 'Publish release to GitHub and the PowerShell Gallery'
        })
        $publishStep | Should -HaveCount 1
        $publishStep[0].shell | Should -Be 'pwsh'
        $publishStep[0].run | Should -Match '\./build\.ps1 -Tasks publish'
    }

    It 'Should keep the module build and both test editions on Windows' {
        $script:workflow.jobs.build.'runs-on' | Should -Be 'windows-latest'
        $script:workflow.jobs.test.'runs-on' | Should -Be 'windows-latest'
        @($script:workflow.jobs.test.strategy.matrix.include.edition) |
            Should -Be @('pwsh', 'powershell-5.1')
    }

    It 'Should retain the standard release, Gallery, and wiki task order' {
        @($script:buildConfiguration.BuildWorkflow.publish) | Should -Be @(
            'Publish_Release_To_GitHub'
            'Publish_Module_To_Gallery'
            'Publish_GitHub_Wiki_Content'
        )
    }

    It 'Should not override the imported wiki task locally' {
        $localWikiTasks = @(
            foreach ($taskFile in Get-ChildItem (Join-Path $script:repositoryRoot '.build') -Filter '*.ps1' -Recurse) {
                $parseErrors = $null
                $taskAst = [System.Management.Automation.Language.Parser]::ParseFile(
                    $taskFile.FullName, [ref] $null, [ref] $parseErrors
                )
                $parseErrors | Should -BeNullOrEmpty
                $taskAst.FindAll({
                    param($node)

                    $node -is [System.Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -eq 'task' -and
                        $node.CommandElements.Count -gt 1 -and
                        $node.CommandElements[1].Extent.Text.Trim("'", '"') -eq 'Publish_GitHub_Wiki_Content'
                }, $true)
            }
        )
        $localWikiTasks | Should -HaveCount 0
    }
}