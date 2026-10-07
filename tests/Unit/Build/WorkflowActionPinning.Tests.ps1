BeforeAll {
    $script:repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    $script:workflowDirectory = Join-Path $script:repositoryRoot '.github/workflows'

    # A step reference looks like 'uses: owner/repo@<sha> # v1.2.3'. The version
    # comment is the only human-readable record of what the SHA points at, so the
    # raw text is read instead of the parsed document, which drops comments.
    $script:actionReference = @(
        foreach ($workflowFile in Get-ChildItem -Path $script:workflowDirectory -Include '*.yml', '*.yaml' -File -Recurse)
        {
            $lineNumber = 0

            foreach ($line in (Get-Content -Path $workflowFile.FullName))
            {
                $lineNumber++

                if ($line -notmatch '^\s*(-\s+)?uses:\s*(?<reference>\S+)\s*(#\s*(?<comment>.*?)\s*)?$')
                {
                    continue
                }

                # A local composite action is referenced by path and cannot carry a
                # SHA pin, so only published actions are checked.
                if ($Matches.reference -match '^\.{1,2}/')
                {
                    continue
                }

                [pscustomobject] @{
                    File       = $workflowFile.Name
                    LineNumber = $lineNumber
                    Reference  = $Matches.reference
                    Comment    = $Matches.comment
                }
            }
        }
    )
}

Describe 'Workflow action pinning' {
    It 'Should reference at least one published action' {
        $script:actionReference | Should -Not -BeNullOrEmpty
    }

    It 'Should pin every published action to a 40-character commit SHA' {
        foreach ($reference in $script:actionReference)
        {
            $reference.Reference |
                Should -Match '^[\w.-]+/[\w./-]+@[0-9a-f]{40}$' -Because (
                    '{0} line {1} must pin a commit SHA, not a mutable tag' -f
                        $reference.File, $reference.LineNumber
                )
        }
    }

    It 'Should name the pinned version in a trailing comment' {
        foreach ($reference in $script:actionReference)
        {
            $reference.Comment |
                Should -Match '^v\d+(\.\d+){0,2}$' -Because (
                    '{0} line {1} ({2}) must record the version the SHA points at' -f
                        $reference.File, $reference.LineNumber, $reference.Reference
                )
        }
    }

    # GitHub forces an action whose action.yml declares node20 onto the Node.js 24
    # runtime and warns on every run. These are the first release lines of each
    # action that declare node24 themselves: checkout v5.0.0, upload-artifact
    # v6.0.0, and download-artifact v7.0.0. A higher line keeps passing, so a
    # later dependency update needs no change here.
    It 'Should keep <Action> on a release line that declares Node.js 24' -ForEach @(
        @{ Action = 'actions/checkout'; EarliestNode24Major = 5 }
        @{ Action = 'actions/upload-artifact'; EarliestNode24Major = 6 }
        @{ Action = 'actions/download-artifact'; EarliestNode24Major = 7 }
    ) {
        $reference = @($script:actionReference | Where-Object -FilterScript {
                $_.Reference -like ('{0}@*' -f $Action)
            })

        $reference | Should -Not -BeNullOrEmpty -Because (
            'the build workflow uses {0}' -f $Action
        )

        foreach ($usage in $reference)
        {
            [int] (($usage.Comment -replace '^v') -split '\.')[0] |
                Should -BeGreaterOrEqual $EarliestNode24Major -Because (
                    '{0} line {1} pins {2}, which runs on the deprecated Node.js 20' -f
                        $usage.File, $usage.LineNumber, $usage.Comment
                )
        }
    }

    It 'Should pin the same SHA for every usage of one action' {
        $inconsistentAction = @(
            $script:actionReference |
                Group-Object -Property { ($_.Reference -split '@')[0] } |
                Where-Object -FilterScript {
                    @($_.Group.Reference | Sort-Object -Unique).Count -gt 1
                }
        )

        $inconsistentAction.Name | Should -BeNullOrEmpty -Because (
            'one workflow run must not mix two versions of the same action'
        )
    }
}
