BeforeDiscovery {
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path

    <#
        If the QA tests are run outside of the build script (e.g with Invoke-Pester)
        the parent scope has not set the variable $ProjectName.
    #>
    if (-not $ProjectName)
    {
        # Assuming project folder name is project name.
        $ProjectName = Get-SamplerProjectName -BuildRoot $projectPath
    }

    $script:moduleName = $ProjectName

    $mut = Get-Module -Name $script:moduleName -ListAvailable |
        Select-Object -First 1 |
            Import-Module -ErrorAction Stop -PassThru

    <#
        The test phase must not re-import the module under test, because a read
        of the module file that misses the engine script-block cache compiles a
        second copy of every module-defined type and strands every script-side
        reference to the first one (OI-31). That leaves this suite dependent on
        how the module was already loaded, so say so here rather than letting
        every discovery-driven quality gate fail one by one.
    #>
    $loaded = @(Get-Module -Name $script:moduleName)

    if ($loaded.Count -ne 1)
    {
        throw (
            "'$script:moduleName' is loaded $($loaded.Count) time(s) in this process, and " +
            'this suite needs exactly one instance to describe.'
        )
    }

    if (-not $loaded[0].ExportedFormatFiles)
    {
        throw (
            "'$script:moduleName' is loaded with no format data, which is what a manifest " +
            "supplies, and it exports $($loaded[0].ExportedFunctions.Count) functions. A " +
            'documentation task imports the root module directly, so check whether the docs ' +
            'and test workflows are sharing one process; build.yaml puts docs in pack and ' +
            'the CI workflow runs them as separate jobs.'
        )
    }
}

BeforeAll {
    # Convert-Path required for PS7 or Join-Path fails
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    # Get git-related project path. This is relevant for modules that will not be deployed in the root folder of Git.
    $gitTopLevelPath = (&git rev-parse --show-toplevel)
    $gitRelatedModulePath = (($projectPath -replace [regex]::Escape([IO.Path]::DirectorySeparatorChar), '/') -replace $gitTopLevelPath, '')
    if (-not [string]::IsNullOrEmpty($gitRelatedModulePath)) { $gitRelatedModulePath = $gitRelatedModulePath.Trim('/')  + '/' }
    $escapedGitRelatedModulePath = [regex]::Escape($gitRelatedModulePath)

    <#
        If the QA tests are run outside of the build script (e.g with Invoke-Pester)
        the parent scope has not set the variable $ProjectName.
    #>
    if (-not $ProjectName)
    {
        # Assuming project folder name is project name.
        $ProjectName = Get-SamplerProjectName -BuildRoot $projectPath
    }

    $script:moduleName = $ProjectName

    $sourcePath = (
        Get-ChildItem -Path $projectPath\*\*.psd1 |
            Where-Object -FilterScript {
                ($_.Directory.Name -match 'source|src' -or $_.Directory.Name -eq $_.BaseName) `
                    -and $(
                    try
                    {
                        Test-ModuleManifest -Path $_.FullName -ErrorAction Stop
                    }
                    catch
                    {
                        $false
                    }
                )
            }
    ).Directory.FullName
}

Describe 'Changelog Management' -Tag 'Changelog' {
    It 'Changelog has been updated' -Skip:(
        -not ([bool](Get-Command git -ErrorAction SilentlyContinue) -and
            [bool](&(Get-Process -Id $PID).Path -NoProfile -Command 'git rev-parse --is-inside-work-tree 2>$null') -and
            [bool](&(Get-Process -Id $PID).Path -NoProfile -Command 'git rev-parse --verify HEAD 2>$null'))
    ) {
        <#
            Get the list of changed files compared with branch main to verify
            that required files are changed.
        #>

        $filesChanged = @()
        # Only run if there is a remote called origin
        if (((git remote) -match 'origin'))
        {
            $headCommit = &git rev-parse HEAD
            $defaultBranchCommit = &git rev-parse origin/main
            $filesChanged += (&git @('diff', "$defaultBranchCommit...$headCommit", '--name-only') |
                Where-Object { $_ -match "^$escapedGitRelatedModulePath" }) -replace "^$escapedGitRelatedModulePath", ""
        }

        $filesStagedAndUnstaged = (&git @('diff', 'HEAD', '--name-only') 2>&1 |
            Where-Object { $_ -match "^$escapedGitRelatedModulePath" }) -replace "^$escapedGitRelatedModulePath", ""

        $filesChanged += $filesStagedAndUnstaged

        # Only check if there are any changed files.
        if ($filesChanged)
        {
            $filesChanged | Should -Contain 'CHANGELOG.md' -Because 'the CHANGELOG.md must be updated with at least one entry in the Unreleased section for each PR'
        }
    }

    It 'Changelog format compliant with keepachangelog format' -Skip:(![bool](Get-Command git -EA SilentlyContinue)) {
        { Get-ChangelogData -Path (Join-Path $ProjectPath 'CHANGELOG.md') -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Changelog should have an Unreleased header' -Skip:$skipTest {
            (Get-ChangelogData -Path (Join-Path -Path $ProjectPath -ChildPath 'CHANGELOG.md') -ErrorAction Stop).Unreleased | Should -Not -BeNullOrEmpty
    }
}

Describe 'General module control' -Tags 'FunctionalQuality' {
    It 'Should import and remove without errors' {
        # The cycle runs in a child process. Importing the module a second time
        # in this one compiles it again whenever the read misses the engine
        # script-block cache, and every module-defined type would then exist
        # twice for the rest of the run.
        $job = Start-Job -ScriptBlock {
            param($ModuleName)

            Import-Module -Name $ModuleName -ErrorAction Stop
            $imported = [bool](Get-Module -Name $ModuleName)

            Remove-Module -Name $ModuleName -ErrorAction Stop

            [pscustomobject]@{
                Imported = $imported
                Removed  = -not (Get-Module -Name $ModuleName)
            }
        } -ArgumentList $script:moduleName

        try {
            Wait-Job -Job $job -Timeout 300 | Should -Not -BeNullOrEmpty
            $result = Receive-Job -Job $job -ErrorAction Stop

            $result.Imported | Should -BeTrue
            $result.Removed | Should -BeTrue
        } finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

BeforeDiscovery {
    # Public quality gates apply to the module's exported command contract.
    $allModuleFunctions = Get-Command -Module $script:moduleName -CommandType Function

    # Build test cases.
    $testCases = @()

    foreach ($function in $allModuleFunctions)
    {
        $testCases += @{
            Name = $function.Name
        }
    }
}

Describe 'Quality for module' -Tags 'TestQuality' {
    BeforeDiscovery {
        if (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)
        {
            $scriptAnalyzerRules = Get-ScriptAnalyzerRule
        }
        else
        {
            if ($ErrorActionPreference -ne 'Stop')
            {
                Write-Warning -Message 'ScriptAnalyzer not found!'
            }
            else
            {
                throw 'ScriptAnalyzer not found!'
            }
        }
    }

    It 'Should have a unit test for <Name>' -ForEach $testCases {
        Get-ChildItem -Path 'tests\' -Recurse -Include "$Name.Tests.ps1" | Should -Not -BeNullOrEmpty
    }

    It 'Should pass Script Analyzer for <Name>' -ForEach $testCases -Skip:(-not $scriptAnalyzerRules) {
        $functionFile = Get-ChildItem -Path $sourcePath -Recurse -Include "$Name.ps1"

        $pssaResult = (Invoke-ScriptAnalyzer -Path $functionFile.FullName)
        $report = $pssaResult | Format-Table -AutoSize | Out-String -Width 110
        $pssaResult | Should -BeNullOrEmpty -Because `
            "some rule triggered.`r`n`r`n $report"
    }
}

Describe 'Help for module' -Tags 'helpQuality' {
    It 'Should have .SYNOPSIS for <Name>' -ForEach $testCases {
        $functionFile = Get-ChildItem -Path $sourcePath -Recurse -Include "$Name.ps1"

        $scriptFileRawContent = Get-Content -Raw -Path $functionFile.FullName

        $abstractSyntaxTree = [System.Management.Automation.Language.Parser]::ParseInput($scriptFileRawContent, [ref] $null, [ref] $null)

        $astSearchDelegate = { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }

        $parsedFunction = $abstractSyntaxTree.FindAll( $astSearchDelegate, $true ) |
            Where-Object -FilterScript {
                $_.Name -eq $Name
            }

        $functionHelp = $parsedFunction.GetHelpContent()

        $functionHelp.Synopsis | Should -Not -BeNullOrEmpty
    }

    It 'Should have a .DESCRIPTION with length greater than 40 characters for <Name>' -ForEach $testCases {
        $functionFile = Get-ChildItem -Path $sourcePath -Recurse -Include "$Name.ps1"

        $scriptFileRawContent = Get-Content -Raw -Path $functionFile.FullName

        $abstractSyntaxTree = [System.Management.Automation.Language.Parser]::ParseInput($scriptFileRawContent, [ref] $null, [ref] $null)

        $astSearchDelegate = { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }

        $parsedFunction = $abstractSyntaxTree.FindAll($astSearchDelegate, $true) |
            Where-Object -FilterScript {
                $_.Name -eq $Name
            }

        $functionHelp = $parsedFunction.GetHelpContent()

        $functionHelp.Description.Length | Should -BeGreaterThan 40
    }

    It 'Should have at least one (1) example for <Name>' -ForEach $testCases {
        $functionFile = Get-ChildItem -Path $sourcePath -Recurse -Include "$Name.ps1"

        $scriptFileRawContent = Get-Content -Raw -Path $functionFile.FullName

        $abstractSyntaxTree = [System.Management.Automation.Language.Parser]::ParseInput($scriptFileRawContent, [ref] $null, [ref] $null)

        $astSearchDelegate = { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }

        $parsedFunction = $abstractSyntaxTree.FindAll( $astSearchDelegate, $true ) |
            Where-Object -FilterScript {
                $_.Name -eq $Name
            }

        $functionHelp = $parsedFunction.GetHelpContent()

        $functionHelp.Examples.Count | Should -BeGreaterThan 0
        $functionHelp.Examples[0] | Should -Match ([regex]::Escape($function.Name))
        $functionHelp.Examples[0].Length | Should -BeGreaterThan ($function.Name.Length + 10)

    }

    It 'Should have described all parameters for <Name>' -ForEach $testCases {
        $functionFile = Get-ChildItem -Path $sourcePath -Recurse -Include "$Name.ps1"

        $scriptFileRawContent = Get-Content -Raw -Path $functionFile.FullName

        $abstractSyntaxTree = [System.Management.Automation.Language.Parser]::ParseInput($scriptFileRawContent, [ref] $null, [ref] $null)

        $astSearchDelegate = { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }

        $parsedFunction = $abstractSyntaxTree.FindAll( $astSearchDelegate, $true ) |
            Where-Object -FilterScript {
                $_.Name -eq $Name
            }

        $functionHelp = $parsedFunction.GetHelpContent()

        $parameters = $parsedFunction.Body.ParamBlock.Parameters.Name.VariablePath.ForEach({ $_.ToString() })

        foreach ($parameter in $parameters)
        {
            $functionHelp.Parameters.($parameter.ToUpper()) | Should -Not -BeNullOrEmpty -Because ('the parameter {0} must have a description' -f $parameter)
            $functionHelp.Parameters.($parameter.ToUpper()).Length | Should -BeGreaterThan 25 -Because ('the parameter {0} must have descriptive description' -f $parameter)
        }
    }
}
