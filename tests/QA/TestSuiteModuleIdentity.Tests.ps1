# The repository gate runs tests/QA, tests/Unit and tests/Integration in one
# PowerShell process, and that process must compile the module under test
# exactly once (OI-31).
#
# PowerShell compiles a module file into a dynamic assembly that carries every
# class and enumeration the file declares, and it caches the compiled script
# block keyed by file path and file content. An import that reads the module
# file when that cache does not hold it compiles the file again, so a second
# copy of every module-defined type goes live. The engine drops the cache whole
# once it holds more than 1024 entries, which is the documented way to get
# there; a real build and test process peaked at 528 entries when it was
# measured, so the trigger that produced the recorded failures was never
# reproduced by running the suite. These rules therefore remove the precondition
# rather than one trigger: a module file that is read once cannot be compiled
# twice, whatever the cache does.
#
# The consequence is what makes it worth guarding. Nothing written in script can
# name the newer copy. A type literal, a literal evaluated in the module's own
# scope, a script block bound to the module, `-as [type]`, a `[type]` cast and
# `Invoke-Expression` all keep resolving the first copy, while the module's own
# commands emit the second, so a strict type assertion on a value the module
# produced fails with the signature `Expected [X], but got [X]`.
BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:moduleManifestPath = (
        Get-ChildItem -Path (
            Join-Path $script:repositoryRoot 'output\module\WindowsAccessControl\*\WindowsAccessControl.psd1'
        ) | Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
    ).FullName

    $gatePaths = @(
        Join-Path $script:repositoryRoot 'tests\QA'
        Join-Path $script:repositoryRoot 'tests\Unit'
        Join-Path $script:repositoryRoot 'tests\Integration'
    )

    $script:moduleLoadCalls = foreach ($file in (
            Get-ChildItem -Path $gatePaths -Recurse -File -Filter '*.ps1'
        )) {
        $tokens = $null
        $parseErrors = $null
        $fileAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName, [ref]$tokens, [ref]$parseErrors
        )
        if ($parseErrors) {
            throw "Cannot parse '$($file.FullName)': $($parseErrors[0].Message)"
        }

        $resolvesModuleUnderTest =
            $fileAst.Extent.Text -match 'output\\module\\WindowsAccessControl'

        $calls = $fileAst.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -in @('Import-Module', 'Remove-Module')
            },
            $true
        )

        foreach ($call in $calls) {
            # A call inside a Start-Job script block runs in a child process and
            # cannot add a type to this one.
            $outOfProcess = $false
            for ($node = $call.Parent; $node; $node = $node.Parent) {
                if ($node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -eq 'Start-Job') {
                    $outOfProcess = $true
                    break
                }
            }

            [pscustomobject]@{
                Location                = '{0}:{1}' -f @(
                    $file.FullName.Substring($script:repositoryRoot.Length + 1)
                    $call.Extent.StartLineNumber
                )
                CommandName             = $call.GetCommandName()
                Text                    = $call.Extent.Text -replace '\s+', ' '
                OutOfProcess            = $outOfProcess
                ResolvesModuleUnderTest = $resolvesModuleUnderTest
            }
        }
    }
}

Describe 'Test suite module identity' -Tag 'QA' {
    It 'Should never force a re-import of the module under test' {
        $forced = @(
            $script:moduleLoadCalls | Where-Object {
                $_.CommandName -eq 'Import-Module' -and
                -not $_.OutOfProcess -and
                $_.ResolvesModuleUnderTest -and
                $_.Text -match '-Force'
            }
        )

        $forced.Location | Should -BeNullOrEmpty -Because (
            'a forced import reads the module file again, and a read that misses ' +
            'the engine script-block cache compiles a second copy of every ' +
            'module-defined type. Import without -Force, which is a no-op ' +
            'when the module is already loaded, or do the cycle inside Start-Job.'
        )
    }

    It 'Should never unload the module under test inside the gate process' {
        $unloads = @(
            $script:moduleLoadCalls | Where-Object {
                $_.CommandName -eq 'Remove-Module' -and
                -not $_.OutOfProcess -and
                ($_.ResolvesModuleUnderTest -or $_.Text -match 'WindowsAccessControl(?!\.)')
            }
        )

        $unloads.Location | Should -BeNullOrEmpty -Because (
            'the next import has to read the module file again, and a read that ' +
            'misses the engine script-block cache compiles a second copy of ' +
            'every module-defined type. Leave the module loaded, or do the ' +
            'unload cycle inside Start-Job.'
        )
    }

    It 'Should still be true that a second compilation strands every type literal' {
        # This pins the host behaviour the two rules above exist for. It runs in
        # a child process because it deliberately compiles the module twice. If
        # it starts failing, PowerShell changed and the rules need rereading,
        # not deleting.
        $job = Start-Job -ScriptBlock {
            param($ManifestPath)

            $enumName = 'WindowsServiceControlManagerRights'
            $accelerators = [psobject].Assembly.GetType(
                'System.Management.Automation.TypeAccelerators'
            )
            $clearScriptBlockCache = [System.Management.Automation.ScriptBlock].GetMethod(
                'ClearScriptBlockCache',
                [System.Reflection.BindingFlags]::Static -bor
                [System.Reflection.BindingFlags]::NonPublic
            )
            if (-not $clearScriptBlockCache) {
                throw 'ScriptBlock.ClearScriptBlockCache is gone, so the host no longer works the way these rules assume.'
            }

            function Measure-LiveCopy {
                param([string]$Name)

                @(
                    [AppDomain]::CurrentDomain.GetAssemblies() |
                        Where-Object { $_.GetType($Name, $false, $false) }
                ).Count
            }

            Import-Module -Name $ManifestPath -ErrorAction Stop
            $firstCopies = Measure-LiveCopy -Name $enumName
            $firstLiteralIsCurrent = [object]::ReferenceEquals(
                [scriptblock]::Create("[$enumName]").Invoke()[0],
                $accelerators::Get[$enumName]
            )

            $clearScriptBlockCache.Invoke($null, @())
            Import-Module -Name $ManifestPath -Force -ErrorAction Stop

            [pscustomobject]@{
                FirstCopies            = $firstCopies
                FirstLiteralIsCurrent  = $firstLiteralIsCurrent
                SecondCopies           = Measure-LiveCopy -Name $enumName
                SecondLiteralIsCurrent = [object]::ReferenceEquals(
                    [scriptblock]::Create("[$enumName]").Invoke()[0],
                    $accelerators::Get[$enumName]
                )
            }
        } -ArgumentList $script:moduleManifestPath

        try {
            Wait-Job -Job $job -Timeout 300 | Should -Not -BeNullOrEmpty
            $measured = Receive-Job -Job $job -ErrorAction Stop

            $measured.FirstCopies | Should -Be 1
            $measured.FirstLiteralIsCurrent | Should -BeTrue
            $measured.SecondCopies | Should -Be 2
            $measured.SecondLiteralIsCurrent | Should -BeFalse
        } finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
