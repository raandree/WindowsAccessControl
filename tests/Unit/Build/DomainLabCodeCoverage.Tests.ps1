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
