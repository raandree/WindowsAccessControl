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
# reproduced by running the suite. These rules therefore remove the
# precondition rather than one trigger.
#
# They do not make a second compilation structurally impossible, and the
# comment that used to say so was wrong. `Invoke-WindowsAccessControlBatch`
# imports the manifest into a runspace pool in this same process whenever a
# bounded batch has both a throttle limit above one and more than one target,
# so the module file is still read by the module itself. That read was measured
# to yield one live copy throughout, but it is a read these rules cannot see.
# The build's exit block is what covers it.
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

    $gateRoots = @(
        Join-Path $script:repositoryRoot 'tests\QA'
        Join-Path $script:repositoryRoot 'tests\Unit'
        Join-Path $script:repositoryRoot 'tests\Integration'
        Join-Path $script:repositoryRoot 'tests\Lab'
        Join-Path $script:repositoryRoot 'tests\Performance'
    )

    # Calls that load something other than the module under test through a
    # variable, so the call itself cannot say what it loads. Named by location
    # rather than by file, so the rest of each file stays covered.
    $exemptCall = @{
        'tests\Unit\Lab\WindowsAccessControl.DomainLab.Tests.ps1:5'  = 'loads the domain-lab harness'
        'tests\Lab\WindowsAccessControl.DomainLab.Live.Tests.ps1:14' = 'loads the domain-lab harness'
    }

    # This one owns its process, so a load and unload cycle in it cannot strand
    # a type for anything else. The other entry-point scripts need no entry:
    # every module they name is matched below.
    $exemptFile = @(
        'tests\Performance\Measure-NtfsBatchPerformance.ps1'
    )

    # Modules the suites legitimately load beside the one under test. A call
    # that names one of these is not about the module under test.
    $otherModuleName = @(
        'ActiveDirectory'
        'AutomatedLab'
        'Pester'
        'Sampler'
        'powershell-yaml'
        'WindowsAccessControl.DomainLab'
    )

    # Every spelling of the two commands, including the shipped aliases and the
    # module-qualified forms.
    $loadCommandName = @('import-module', 'ipmo', 'microsoft.powershell.core\import-module')
    $unloadCommandName = @('remove-module', 'rmo', 'microsoft.powershell.core\remove-module')

    $script:moduleLoadCalls = foreach ($file in (
            Get-ChildItem -Path $gateRoots -Recurse -File |
                Where-Object Extension -EQ '.ps1'
        )) {
        $relativePath = $file.FullName.Substring($script:repositoryRoot.Length + 1)
        if ($relativePath -in $exemptFile) {
            continue
        }

        $tokens = $null
        $parseErrors = $null
        $fileAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName, [ref]$tokens, [ref]$parseErrors
        )
        if ($parseErrors) {
            throw "Cannot parse '$($file.FullName)': $($parseErrors[0].Message)"
        }

        $calls = $fileAst.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName()
            },
            $true
        )

        foreach ($call in $calls) {
            $commandName = $call.GetCommandName().ToLowerInvariant()
            $isLoad = $commandName -in $loadCommandName
            $isUnload = $commandName -in $unloadCommandName
            if (-not ($isLoad -or $isUnload)) {
                continue
            }

            $location = '{0}:{1}' -f $relativePath, $call.Extent.StartLineNumber
            if ($exemptCall.ContainsKey($location)) {
                continue
            }

            # Only the arguments decide which module a call is about. Reading
            # the whole extent would let a comment or an unrelated path exempt
            # it.
            $argumentText = (
                $call.CommandElements |
                    Select-Object -Skip 1 |
                    Where-Object {
                        $_ -isnot [System.Management.Automation.Language.CommandParameterAst]
                    } |
                    ForEach-Object { $_.Extent.Text }
            ) -join ' '

            if ($otherModuleName | Where-Object { $argumentText -match [regex]::Escape($_) }) {
                continue
            }

            # Start-Job runs in a child process, and Invoke-Command runs on
            # another machine only when it is given a target. Start-ThreadJob is
            # deliberately absent: a thread job shares this process.
            $outOfProcess = $false
            for ($node = $call.Parent; $node; $node = $node.Parent) {
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) {
                    continue
                }

                $ancestorName = $node.GetCommandName()
                if ($ancestorName -eq 'Start-Job' -or $ancestorName -eq 'Invoke-LabCommand') {
                    $outOfProcess = $true
                    break
                }

                if ($ancestorName -eq 'Invoke-Command') {
                    $remoting = $node.CommandElements |
                        Where-Object {
                            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and
                            $_.ParameterName -match '^(Session|ComputerName|VMName|ContainerId)'
                        }

                    if ($remoting) {
                        $outOfProcess = $true
                        break
                    }
                }
            }

            # -Force is read from the parameter list rather than the call text,
            # so an abbreviation cannot slip past. Splatted parameters cannot be
            # read at all, so they count as unproven and stay in scope.
            $forced = $false
            $splatted = $false
            foreach ($element in $call.CommandElements) {
                if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $element.ParameterName -and
                    'Force'.StartsWith($element.ParameterName, [StringComparison]::OrdinalIgnoreCase)) {
                    $forced = $true
                }

                if ($element -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $element.Splatted) {
                    $splatted = $true
                }
            }

            [pscustomobject]@{
                Location     = $location
                IsLoad       = $isLoad
                IsUnload     = $isUnload
                Text         = $call.Extent.Text -replace '\s+', ' '
                OutOfProcess = $outOfProcess
                Forced       = $forced
                Splatted     = $splatted
            }
        }
    }
}

Describe 'Test suite module identity' -Tag 'QA' {
    It 'Should never force a re-import of the module under test' {
        $forced = @(
            $script:moduleLoadCalls | Where-Object {
                $_.IsLoad -and -not $_.OutOfProcess -and ($_.Forced -or $_.Splatted)
            }
        )

        $forced.Location | Should -BeNullOrEmpty -Because (
            'a forced import reads the module file again, and a read that misses ' +
            'the engine script-block cache compiles a second copy of every ' +
            'module-defined type. Import without -Force, which is a no-op ' +
            'when the module is already loaded, or do the cycle inside Start-Job. ' +
            'A splatted parameter set is reported too, because it cannot be read.'
        )
    }

    It 'Should never unload the module under test inside a shared test process' {
        $unloads = @(
            $script:moduleLoadCalls | Where-Object { $_.IsUnload -and -not $_.OutOfProcess }
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
