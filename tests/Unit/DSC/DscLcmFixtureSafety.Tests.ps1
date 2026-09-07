BeforeAll {
    $fixturePath = Join-Path $PSScriptRoot '..\..\Integration\ExactSecurityDescriptorDscLcm.Tests.ps1'
    $parseErrors = $null
    $tokens = $null
    $fixtureAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $fixturePath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw 'The DSC integration fixture could not be parsed.'
    }
    $script:fixtureSetup = $fixtureAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'BeforeAll'
    }, $false).CommandElements[1].ScriptBlock.GetScriptBlock()
    $script:fixtureCleanup = $fixtureAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'AfterAll'
    }, $false).CommandElements[1].ScriptBlock.GetScriptBlock()
}

Describe 'DSC LCM integration fixture ownership' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $fixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $fakeBuildRoot = Join-Path $fixtureRoot 'build'
        $fakeVersionRoot = Join-Path $fakeBuildRoot 'WindowsAccessControl\91.0.0'
        $null = New-Item -Path $fakeVersionRoot -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $fakeVersionRoot 'WindowsAccessControl.psd1') -Value '@{}'
        $fakeProgramFiles = Join-Path $fixtureRoot 'ProgramFiles'
        $script:installedModulePath = Join-Path $fakeProgramFiles 'WindowsPowerShell\Modules\WindowsAccessControl\91.0.0'
        Mock Resolve-Path { [pscustomobject]@{ Path = $fakeBuildRoot } }
        Mock Import-Module { throw 'The fixture must fail before importing a module.' }
    }

    It 'Should preserve a pre-existing installation when setup refuses to overwrite it' {
        $null = New-Item -Path $installedModulePath -ItemType Directory -Force
        $sentinel = Join-Path $installedModulePath 'existing-module.txt'
        Set-Content -LiteralPath $sentinel -Value 'pre-existing installation' -NoNewline
        $originalProgramFiles = $env:ProgramFiles
        try {
            $env:ProgramFiles = $fakeProgramFiles
            try {
                { & $script:fixtureSetup } | Should -Throw '*will not overwrite*'
            } finally {
                & $script:fixtureCleanup
            }

            $sentinel | Should -Exist
            Get-Content -LiteralPath $sentinel -Raw | Should -BeExactly 'pre-existing installation'
            Should -Invoke Import-Module -Exactly -Times 0
        } finally {
            $env:ProgramFiles = $originalProgramFiles
        }
    }

    It 'Should remove an owned partial installation when copying the fixture fails' {
        Mock Copy-Item {
            Set-Content -LiteralPath (Join-Path $Destination 'partial.txt') -Value 'partial copy'
            throw 'Expected fixture copy failure.'
        }
        $originalProgramFiles = $env:ProgramFiles
        try {
            $env:ProgramFiles = $fakeProgramFiles
            try {
                { & $script:fixtureSetup } | Should -Throw '*Expected fixture copy failure*'
            } finally {
                & $script:fixtureCleanup
            }

            $installedModulePath | Should -Not -Exist
            Should -Invoke Import-Module -Exactly -Times 0
        } finally {
            $env:ProgramFiles = $originalProgramFiles
        }
    }

    It 'Should restore the module search path when cleanup fails' {
        Mock Import-Module { }
        Mock Remove-Item { throw 'Expected fixture cleanup failure.' } -ParameterFilter {
            $LiteralPath -eq $installedModulePath
        }
        $originalProgramFiles = $env:ProgramFiles
        $originalModulePath = $env:PSModulePath
        try {
            $env:ProgramFiles = $fakeProgramFiles
            & $script:fixtureSetup
            $env:PSModulePath = 'temporary fixture search path'

            { & $script:fixtureCleanup } | Should -Throw '*Expected fixture cleanup failure*'

            $env:PSModulePath | Should -BeExactly $originalModulePath
        } finally {
            $env:ProgramFiles = $originalProgramFiles
            $env:PSModulePath = $originalModulePath
        }
    }
}