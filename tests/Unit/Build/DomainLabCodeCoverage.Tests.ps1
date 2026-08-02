BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    . (Join-Path $script:repositoryRoot '.build\JaCoCoDocument.ps1')
    Import-Module -Name 'Sampler' -ErrorAction Stop

    function script:New-TestJaCoCoDocument {
        param(
            [string]$Package = '1.2.3',
            [string]$SourceFile = 'WindowsAccessControl.psm1',
            [hashtable]$Lines = @{ 10 = @(1, 0); 20 = @(0, 1) }
        )

        $lineElements = @(
            foreach ($number in ($Lines.Keys | Sort-Object)) {
                '<line nr="{0}" mi="{1}" ci="{2}" mb="0" cb="0"/>' -f
                    $number, $Lines[$number][0], $Lines[$number][1]
            }
        ) -join ''
        $counters = {
            param([string[]]$Type)

            (@(
                    foreach ($name in $Type) {
                        '<counter type="{0}" missed="0" covered="0"/>' -f $name
                    }
                ) -join '')
        }

        [xml](@(
                '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
                '<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
                '<report name="Pester">'
                '<sessioninfo id="this" start="0" dump="1"/>'
                ('<package name="{0}">' -f $Package)
                ('<class name="{0}/{1}" sourcefilename="{2}">' -f
                    $Package, [IO.Path]::GetFileNameWithoutExtension($SourceFile), $SourceFile)
                '<method name="Get-Thing" desc="()" line="10">'
                (& $counters -Type 'INSTRUCTION', 'LINE', 'METHOD')
                '</method>'
                (& $counters -Type 'INSTRUCTION', 'LINE', 'METHOD', 'CLASS')
                '</class>'
                ('<sourcefile name="{0}">' -f $SourceFile)
                $lineElements
                (& $counters -Type 'INSTRUCTION', 'LINE', 'METHOD', 'CLASS')
                '</sourcefile>'
                (& $counters -Type 'INSTRUCTION', 'LINE', 'METHOD', 'CLASS')
                '</package>'
                (& $counters -Type 'INSTRUCTION', 'LINE', 'METHOD', 'CLASS')
                '</report>'
            ) -join '')
    }

    function script:New-TestBuiltModule {
        param(
            [hashtable[]]$Region
        )

        $lines = [System.Collections.Generic.List[string]]::new()

        foreach ($entry in $Region) {
            $lines.Add(("#Region '{0}' -1" -f $entry.Path))

            for ($index = 1; $index -le [int]$entry.LineCount; $index++) {
                $lines.Add(('$null = {0}' -f $index))
            }

            $lines.Add(("#EndRegion '{0}' {1}" -f $entry.Path, $entry.LineCount))
            $lines.Add('')
        }

        $path = Join-Path -Path $TestDrive -ChildPath ('{0}.psm1' -f [guid]::NewGuid())
        Set-Content -Path $path -Value $lines -Encoding 'ascii'

        $path
    }
}

Describe 'Domain-lab code coverage merge inputs' {
    It 'Should count commands from the line elements rather than the counters' {
        $document = script:New-TestJaCoCoDocument -Lines @{ 10 = @(3, 0); 20 = @(1, 4) }

        $count = Get-JaCoCoCommandCount -Document $document

        $count.Analyzed | Should -Be 8
        $count.Executed | Should -Be 4
        $count.Missed | Should -Be 4
        [math]::Round($count.Percent, 2) | Should -Be 50
    }

    It 'Should leave the measured commands unchanged when no domain-lab coverage exists' {
        $localDocument = script:New-TestJaCoCoDocument -Lines @{ 10 = @(3, 0); 20 = @(1, 4) }
        [xml]$emptyDocument = Get-EmptyJaCoCoDocument -Name 'domain lab (absent)'
        $before = Get-JaCoCoCommandCount -Document $localDocument

        $merged = Merge-JaCoCoReport -OriginalDocument $localDocument -MergeDocument $emptyDocument
        $merged = Update-JaCoCoStatistic -Document $merged
        $after = Get-JaCoCoCommandCount -Document $merged

        $after.Analyzed | Should -Be $before.Analyzed
        $after.Executed | Should -Be $before.Executed
    }

    It 'Should raise the executed commands without changing the analyzed commands when the lab covers a missed line' {
        $localDocument = script:New-TestJaCoCoDocument -Lines @{ 10 = @(3, 0); 20 = @(1, 4) }
        $domainLabDocument = script:New-TestJaCoCoDocument -Lines @{ 10 = @(0, 3); 20 = @(5, 0) }

        $merged = Merge-JaCoCoReport -OriginalDocument $localDocument -MergeDocument $domainLabDocument
        $merged = Update-JaCoCoStatistic -Document $merged
        $after = Get-JaCoCoCommandCount -Document $merged

        $after.Analyzed | Should -Be 8
        $after.Executed | Should -Be 7
    }

    It 'Should refuse a domain-lab document that measures another source file' {
        $localDocument = script:New-TestJaCoCoDocument
        $domainLabDocument = script:New-TestJaCoCoDocument -Package '9.9.9'

        {
            Assert-JaCoCoDocumentIdentity `
                -ReferenceDocument $localDocument `
                -Document $domainLabDocument
        } | Should -Throw -ExpectedMessage '*measures source files the local run does not*'
    }

    It 'Should refuse a domain-lab document that measures lines the local run does not' {
        $localDocument = script:New-TestJaCoCoDocument -Lines @{ 10 = @(1, 0) }
        $domainLabDocument = script:New-TestJaCoCoDocument -Lines @{ 10 = @(0, 1); 999 = @(0, 1) }

        {
            Assert-JaCoCoDocumentIdentity `
                -ReferenceDocument $localDocument `
                -Document $domainLabDocument
        } | Should -Throw -ExpectedMessage '*measures 1 line(s) the local run does not*'
    }
}

Describe 'Domain-lab code coverage scope' {
    BeforeAll {
        $script:builtModulePath = script:New-TestBuiltModule -Region @(
            @{ Path = '.\Public\Get-Thing.ps1'; LineCount = 3 }
            @{ Path = '.\Private\Get-Secret.ps1'; LineCount = 3 }
        )
    }

    It 'Should map only the lines a source region encloses' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath

        $map[2] | Should -Be 'Public/Get-Thing.ps1'
        $map[4] | Should -Be 'Public/Get-Thing.ps1'
        $map[8] | Should -Be 'Private/Get-Secret.ps1'
        $map.ContainsKey(1) | Should -BeFalse
        $map.ContainsKey(5) | Should -BeFalse
        $map.ContainsKey(6) | Should -BeFalse
    }

    It 'Should attribute measured commands to the source file they were merged from' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 2 = @(1, 3); 8 = @(2, 0) }

        $coverage = Get-JaCoCoSourceCoverage -Document $document -SourceMap $map

        ($coverage | Where-Object { $_.SourcePath -eq 'Public/Get-Thing.ps1' }).Executed | Should -Be 3
        ($coverage | Where-Object { $_.SourcePath -eq 'Private/Get-Secret.ps1' }).Missed | Should -Be 2
    }

    It 'Should keep a line the source map cannot attribute inside the asserted scope' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 6 = @(5, 0); 8 = @(0, 1) }

        $scoped = Get-JaCoCoScopedCommandCount `
            -Document $document `
            -SourceMap $map `
            -DomainLabOnlySourcePath @('Private/*')

        $scoped.InScope.Analyzed | Should -Be 5
        $scoped.DomainLabOnly.Analyzed | Should -Be 1
    }

    It 'Should raise the in-scope percentage above the whole-module percentage when a declared source file is missed' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 2 = @(1, 9); 8 = @(10, 0) }

        $whole = Get-JaCoCoCommandCount -Document $document
        $scoped = Get-JaCoCoScopedCommandCount `
            -Document $document `
            -SourceMap $map `
            -DomainLabOnlySourcePath @('Private/Get-Secret.ps1')

        [math]::Round($whole.Percent, 2) | Should -Be 45
        [math]::Round($scoped.InScope.Percent, 2) | Should -Be 90
        $scoped.DomainLabOnly.Executed | Should -Be 0
        $scoped.DomainLabOnlySource.SourcePath | Should -Be 'Private/Get-Secret.ps1'
    }

    It 'Should report the executed commands of a declared source file so the build can refuse it' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 2 = @(0, 1); 8 = @(3, 4) }

        $scoped = Get-JaCoCoScopedCommandCount `
            -Document $document `
            -SourceMap $map `
            -DomainLabOnlySourcePath @('Private/Get-Secret.ps1')

        @($scoped.DomainLabOnlySource | Where-Object { $_.Executed -gt 0 }).Count | Should -Be 1
        ($scoped.DomainLabOnlySource | Where-Object { $_.Executed -gt 0 }).Executed | Should -Be 4
    }

    It 'Should report the commands the source map cannot attribute' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 6 = @(5, 2); 8 = @(0, 1) }

        $scoped = Get-JaCoCoScopedCommandCount `
            -Document $document `
            -SourceMap $map `
            -DomainLabOnlySourcePath @('Private/*')

        $scoped.Unattributed.Analyzed | Should -Be 7
        $scoped.Unattributed.Executed | Should -Be 2
    }

    It 'Should report a declared pattern that matches no source file' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 2 = @(0, 1) }

        $scoped = Get-JaCoCoScopedCommandCount `
            -Document $document `
            -SourceMap $map `
            -DomainLabOnlySourcePath @('Public/Get-Thing.ps1', 'Public/Get-Removed.ps1')

        $scoped.UnmatchedPattern | Should -Be 'Public/Get-Removed.ps1'
    }

    It 'Should measure every command when nothing is declared domain-lab-only' {
        $map = Get-BuiltModuleSourceMap -Path $script:builtModulePath
        $document = script:New-TestJaCoCoDocument -Lines @{ 2 = @(1, 3); 8 = @(2, 0) }

        $whole = Get-JaCoCoCommandCount -Document $document
        $scoped = Get-JaCoCoScopedCommandCount -Document $document -SourceMap $map

        $scoped.InScope.Analyzed | Should -Be $whole.Analyzed
        $scoped.InScope.Executed | Should -Be $whole.Executed
        $scoped.DomainLabOnly.Analyzed | Should -Be 0
    }
}

Describe 'Declared domain-lab-only source paths' {
    BeforeAll {
        Import-Module -Name 'powershell-yaml' -ErrorAction Stop

        $script:buildConfiguration = ConvertFrom-Yaml -Yaml (
            Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'build.yaml') -Raw
        )
        $script:declaredPath = @($script:buildConfiguration.CodeCoverage.DomainLabOnlySourcePath)
    }

    It 'Should declare at least one source path' {
        $script:declaredPath.Count | Should -BeGreaterThan 0
    }

    It 'Should declare only source files that exist' {
        foreach ($relativePath in $script:declaredPath) {
            Join-Path $script:repositoryRoot (Join-Path 'source' $relativePath) | Should -Exist
        }
    }

    It 'Should declare exact paths rather than wildcards' {
        foreach ($relativePath in $script:declaredPath) {
            $relativePath | Should -Not -Match '[\*\?\[]'
        }
    }
}
