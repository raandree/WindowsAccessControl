# Specification conformance for NFR-4 and ADR 0001.
BeforeAll {
    $script:repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    $script:specRoot = Join-Path $script:repositoryRoot 'specs'
    $script:decisionRoot = Join-Path $script:specRoot 'decisions'
    $script:coreSpecifications = @(
        '0001-vision-and-scope.md'
        '0002-requirements.md'
        '0003-public-api.md'
        '0004-security-and-persistence.md'
        '0005-verification-and-traceability.md'
    )
}

Describe 'Specification contract' -Tag 'QA', 'Specifications' {
    It 'Should keep each changelog category unique within a release' {
        $changelog = Get-Content -LiteralPath (
            Join-Path $script:repositoryRoot 'CHANGELOG.md'
        ) -Raw
        $releases = [regex]::Matches(
            $changelog, '(?ms)^## (?<Version>[^\r\n]+)\r?\n(?<Changes>.*?)(?=^## |\z)'
        )
        $releases.Count | Should -BeGreaterThan 0
        foreach ($release in $releases) {
            $categories = @([regex]::Matches(
                $release.Groups['Changes'].Value, '(?m)^### ([^\r\n]+)'
            ) | ForEach-Object { $_.Groups[1].Value })
            $categories.Count | Should -Be (@($categories | Sort-Object -Unique).Count) -Because (
                'release {0} must not repeat a category' -f $release.Groups['Version'].Value
            )
        }
    }

    It 'Should contain the indexed specification structure' {
        $requiredPaths = @(
            'README.md'
            'open-issues.md'
            'decisions\README.md'
            'decisions\0000-use-architecture-decision-records.md'
        ) + $script:coreSpecifications

        foreach ($relativePath in $requiredPaths) {
            Join-Path $script:specRoot $relativePath | Should -Exist
        }
    }

    It 'Should index every numbered specification' {
        $index = Get-Content -LiteralPath (Join-Path $script:specRoot 'README.md') -Raw
        $specifications = @(Get-ChildItem -LiteralPath $script:specRoot -File |
            Where-Object Name -Match '^\d{4}-.+\.md$')

        $specifications | Should -Not -BeNullOrEmpty
        foreach ($specification in $specifications) {
            $index | Should -Match ([regex]::Escape($specification.Name))
            $heading = Get-Content -LiteralPath $specification.FullName -TotalCount 5
            $heading -join "`n" | Should -MatchExactly '(?m)^Status: (Draft|Accepted|Superseded)\.'
        }
    }

    It 'Should define unique stable requirement identifiers' {
        $requirementsPath = Join-Path $script:specRoot '0002-requirements.md'
        $requirements = Get-Content -LiteralPath $requirementsPath -Raw
        $identifiers = @([regex]::Matches(
            $requirements,
            '\b(?:FR|NFR)-\d+\b'
        ).Value)

        $identifiers | Should -Not -BeNullOrEmpty
        $identifiers.Count | Should -Be (@($identifiers | Sort-Object -Unique).Count)
    }

    It 'Should trace every requirement to executable evidence' {
        $requirements = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0002-requirements.md'
        ) -Raw
        $traceability = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0005-verification-and-traceability.md'
        ) -Raw
        $identifiers = @([regex]::Matches(
            $requirements,
            '\b(?:FR|NFR)-\d+\b'
        ).Value | Sort-Object -Unique)

        foreach ($identifier in $identifiers) {
            $traceability | Should -Match ([regex]::Escape($identifier))
        }
    }

    It 'Should include every exported command in the public API contract' {
        $manifest = Test-ModuleManifest (
            Join-Path $script:repositoryRoot 'source\WindowsAccessControl.psd1'
        ) -ErrorAction Stop
        $apiContract = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0003-public-api.md'
        ) -Raw

        foreach ($commandName in $manifest.ExportedFunctions.Keys) {
            $contractToken = [char]96 + $commandName + [char]96
            $apiContract | Should -Match ([regex]::Escape($contractToken))
        }
    }

    It 'Should reference every requirement from a test-suite comment' {
        $requirements = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0002-requirements.md'
        ) -Raw
        $identifiers = @([regex]::Matches($requirements, '\b(?:FR|NFR)-\d+\b').Value |
            Sort-Object -Unique)
        $comments = foreach ($testFile in Get-ChildItem -LiteralPath (
            Join-Path $script:repositoryRoot 'tests'
        ) -Recurse -File -Filter '*.Tests.ps1') {
            $tokens = $null
            $parseErrors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $testFile.FullName, [ref]$tokens, [ref]$parseErrors
            )
            $parseErrors | Should -BeNullOrEmpty -Because $testFile.Name
            $tokens | Where-Object Kind -eq 'Comment' | ForEach-Object Text
        }
        $references = @([regex]::Matches(
            ($comments -join "`n"), '\b(?:FR|NFR)-\d+\b'
        ).Value | Sort-Object -Unique)

        Compare-Object -ReferenceObject $identifiers -DifferenceObject $references |
            Should -BeNullOrEmpty
    }

    It 'Should document every exported command exactly once in the evidence table' {
        $manifest = Import-PowerShellDataFile (
            Join-Path $script:repositoryRoot 'source\WindowsAccessControl.psd1'
        )
        $traceability = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0005-verification-and-traceability.md'
        ) -Raw
        $section = [regex]::Match(
            $traceability,
            '(?ms)^## Public command evidence\r?\n(?<Table>.*?)(?=^## |\z)'
        )
        $section.Success | Should -BeTrue
        $commands = @([regex]::Matches(
            $section.Groups['Table'].Value,
            '(?m)^\| `(?<Command>[^`]+)` \|'
        ) | ForEach-Object { $_.Groups['Command'].Value })

        $commands | Should -Not -BeNullOrEmpty
        $commands.Count | Should -Be (@($commands | Sort-Object -Unique).Count)
        Compare-Object -ReferenceObject $manifest.FunctionsToExport -DifferenceObject $commands |
            Should -BeNullOrEmpty
    }

    It 'Should link every command evidence row to its command-specific suite' {
        $traceability = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0005-verification-and-traceability.md'
        ) -Raw
        $section = [regex]::Match(
            $traceability,
            '(?ms)^## Public command evidence\r?\n(?<Table>.*?)(?=^## |\z)'
        )
        $section.Success | Should -BeTrue
        $rows = [regex]::Matches(
            $section.Groups['Table'].Value,
            '(?m)^\| `(?<Command>[A-Za-z]+-[A-Za-z0-9]+)` \| (?<Evidence>[^|]+) \|'
        )
        $rows.Count | Should -BeGreaterThan 0
        foreach ($row in $rows) {
            $commandName = $row.Groups['Command'].Value
            $link = [regex]::Match(
                $row.Groups['Evidence'].Value.Trim(),
                ('^\[Tests\]\(\.\./(?<Path>tests/(?:Unit/Public|Integration)/{0}\.Tests\.ps1)\)$' -f
                    [regex]::Escape($commandName))
            )
            $link.Success | Should -BeTrue -Because "$commandName must link to its actual test suite"
            Join-Path $script:repositoryRoot $link.Groups['Path'].Value | Should -Exist
        }
    }

    It 'Should list the output types declared by public help and selected by format views' {
        $apiContract = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0003-public-api.md'
        ) -Raw
        $section = [regex]::Match($apiContract, '(?ms)^### Output types\r?\n(?<Types>.*?)(?=^## |\z)')
        $section.Success | Should -BeTrue
        $listedTypes = @([regex]::Matches(
            $section.Groups['Types'].Value, '(?m)^- `(WindowsAccessControl\.[A-Za-z0-9]+)`'
        ) | ForEach-Object { $_.Groups[1].Value })
        $listedTypes.Count | Should -Be (@($listedTypes | Sort-Object -Unique).Count)
        $helpTypes = foreach ($commandFile in Get-ChildItem -LiteralPath (
            Join-Path $script:repositoryRoot 'source/Public'
        ) -File -Filter '*.ps1') {
            $content = Get-Content -LiteralPath $commandFile.FullName -Raw
            $outputs = [regex]::Match(
                $content, '(?ms)^\s*\.OUTPUTS\r?\n(?<Outputs>.*?)(?=^\s*(?:\.[A-Z]+|#>))'
            )
            [regex]::Matches($outputs.Groups['Outputs'].Value, 'WindowsAccessControl\.[A-Za-z0-9]+').Value
        }
        [xml]$formatData = Get-Content -LiteralPath (
            Join-Path $script:repositoryRoot 'source/WindowsAccessControl.Format.ps1xml'
        ) -Raw
        $expectedTypes = @($helpTypes) + @(
            $formatData.Configuration.ViewDefinitions.View.ViewSelectedBy.TypeName
        )
        $expectedTypes | Should -Not -BeNullOrEmpty
        foreach ($typeName in $expectedTypes | Sort-Object -Unique) {
            $listedTypes | Should -Contain $typeName
        }
    }

    It 'Should list every exported DSC resource exactly once in the API tables' {
        $manifest = Import-PowerShellDataFile (
            Join-Path $script:repositoryRoot 'source/WindowsAccessControl.psd1'
        )
        $apiContract = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0003-public-api.md'
        ) -Raw
        $resources = @([regex]::Matches(
            $apiContract, '(?m)^\| `(WindowsAccessControl[A-Za-z0-9]+)` \|'
        ) | ForEach-Object { $_.Groups[1].Value })
        $resources | Should -Not -BeNullOrEmpty
        $resources.Count | Should -Be (@($resources | Sort-Object -Unique).Count)
        Compare-Object -ReferenceObject $manifest.DscResourcesToExport -DifferenceObject $resources |
            Should -BeNullOrEmpty
    }

    It 'Should document the exact ordered domain-lab suite inventory' {
        $tokens = $null
        $parseErrors = $null
        $runner = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:repositoryRoot 'tests/Lab/WindowsAccessControl.DomainLab.psm1'),
            [ref]$tokens, [ref]$parseErrors
        )
        $parseErrors | Should -BeNullOrEmpty
        $acceptanceFunction = $runner.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-WindowsAccessControlDomainLabAcceptance'
        }, $true)
        $acceptanceFunction | Should -Not -BeNullOrEmpty
        $assignments = @($acceptanceFunction.Body.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq 'suiteNames'
        }, $true))
        $assignments.Count | Should -Be 1
        $suiteNames = @($assignments[0].Right.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
        }, $true) | ForEach-Object Value)
        $suiteNames | Should -Not -BeNullOrEmpty
        $traceability = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0005-verification-and-traceability.md'
        ) -Raw
        $section = [regex]::Match(
            $traceability, '(?ms)^### Domain-lab suites\r?\n(?<Suites>.*?)(?=^#{1,3} |\z)'
        )
        $section.Success | Should -BeTrue
        $documentedNames = @([regex]::Matches(
            $section.Groups['Suites'].Value, '\]\(\.\./tests/Lab/([^/()]+\.Live\.Tests\.ps1)\)'
        ) | ForEach-Object { $_.Groups[1].Value })
        $documentedNames | Should -Be $suiteNames
        foreach ($suiteName in $suiteNames) {
            Join-Path $script:repositoryRoot "tests/Lab/$suiteName" | Should -Exist
        }
    }

    It 'Should resolve every local specification link' {
        $markdownFiles = @(
            Get-ChildItem -LiteralPath $script:specRoot -Recurse -File -Filter '*.md'
        )
        $brokenLinks = @()

        foreach ($file in $markdownFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($match in [regex]::Matches($content, '\[[^\]]+\]\(([^)]+)\)')) {
                $target = $match.Groups[1].Value
                if ($target -match '^(?:https?://|mailto:|#)') {
                    continue
                }
                $relativePath = ($target -split '#', 2)[0]
                if ([string]::IsNullOrWhiteSpace($relativePath)) {
                    continue
                }
                $resolvedPath = [System.IO.Path]::GetFullPath(
                    (Join-Path $file.DirectoryName $relativePath)
                )
                if (-not (Test-Path -LiteralPath $resolvedPath)) {
                    $brokenLinks += '{0}: {1}' -f $file.Name, $target
                }
            }
        }

        $brokenLinks | Should -BeNullOrEmpty
    }

    It 'Should define curated format views required by the API contract' {
        [xml]$formatData = Get-Content -LiteralPath (
            Join-Path $script:repositoryRoot 'source\WindowsAccessControl.Format.ps1xml'
        ) -Raw
        $formattedTypes = @(
            $formatData.Configuration.ViewDefinitions.View.ViewSelectedBy.TypeName
        )
        $requiredTypes = @(
            'WindowsAccessControl.AccessRule'
            'WindowsAccessControl.AuditRule'
            'WindowsAccessControl.Owner'
            'WindowsAccessControl.EffectiveAccess'
            'WindowsAccessControl.Privilege'
            'WindowsAccessControl.RegistryKeyAccessRule'
            'WindowsAccessControl.RegistryKeyAuditRule'
            'WindowsAccessControl.ServiceAccessRule'
            'WindowsAccessControl.ServiceAuditRule'
            'WindowsAccessControl.ServiceControlManagerAccessRule'
            'WindowsAccessControl.ServiceControlManagerAuditRule'
            'WindowsAccessControl.ProcessAccessRule'
            'WindowsAccessControl.ProcessAuditRule'
            'WindowsAccessControl.SmbShareAccessRule'
            'WindowsAccessControl.TaskFolderAccessRule'
            'WindowsAccessControl.ScheduledTaskAccessRule'
            'WindowsAccessControl.SmbShareEffectiveAccess'
            'WindowsAccessControl.ADObjectAccessRule'
            'WindowsAccessControl.ADObjectCallerEffectiveAccess'
            'WindowsAccessControl.ADSchemaDefaultAccessRule'
            'WindowsAccessControl.CertificatePrivateKeyAccessRule'
        )

        foreach ($typeName in $requiredTypes) {
            $formattedTypes | Should -Contain $typeName
        }

        $smbEffectiveView = @(
            $formatData.Configuration.ViewDefinitions.View |
                Where-Object Name -EQ 'WindowsAccessControl.SmbShareEffectiveAccess'
        )
        $smbEffectiveColumns = @(
            $smbEffectiveView.TableControl.TableRowEntries.TableRowEntry.
                TableColumnItems.TableColumnItem.PropertyName
        )
        $smbEffectiveColumns | Should -Contain 'AuthorizationContext'
        $smbEffectiveColumns | Should -Contain 'IncludesBackingNtfs'

        $directoryEffectiveView = @(
            $formatData.Configuration.ViewDefinitions.View |
                Where-Object Name -EQ 'WindowsAccessControl.ADObjectCallerEffectiveAccess'
        )
        $directoryEffectiveColumns = @(
            $directoryEffectiveView.TableControl.TableRowEntries.TableRowEntry.
                TableColumnItems.TableColumnItem.PropertyName
        )
        $directoryEffectiveColumns | Should -Contain 'Account'
        $directoryEffectiveColumns | Should -Contain 'AuthorizationContext'

        $accessRuleView = @(
            $formatData.Configuration.ViewDefinitions.View |
                Where-Object Name -EQ 'WindowsAccessControl.AccessRule'
        )
        $accessRuleColumns = @(
            $accessRuleView.TableControl.TableRowEntries.TableRowEntry.
                TableColumnItems.TableColumnItem.PropertyName
        )
        $accessRuleColumns | Should -Contain 'InheritedFrom'

        $registryAccessRuleView = @(
            $formatData.Configuration.ViewDefinitions.View |
                Where-Object Name -EQ 'WindowsAccessControl.RegistryKeyAccessRule'
        )
        $registryAccessRuleColumns = @(
            $registryAccessRuleView.TableControl.TableRowEntries.TableRowEntry.
                TableColumnItems.TableColumnItem.PropertyName
        )
        $registryAccessRuleColumns | Should -Contain 'InheritedFrom'
    }

    It 'Should format a private-key rule with <ExpectedIdentity>' -ForEach @(
        @{ Account = 'WAC\Reader'; ExpectedIdentity = 'WAC\Reader' }
        @{ Account = $null; ExpectedIdentity = 'S-1-5-21-111-222-333-444' }
    ) {
        $orphanSid = 'S-1-5-21-111-222-333-444'
        # Format data is process-global, so render in a child process rather
        # than leak a prepended format file into the shared test session.
        $rendered = Start-Job -ScriptBlock {
            param($FormatPath, $Account, $Sid)

            Update-FormatData -PrependPath $FormatPath -ErrorAction Stop
            $rule = [pscustomobject]@{
                KeyName             = 'WacDisplayKey'
                KeyScope            = 'Machine'
                Account             = $Account
                SID                 = $Sid
                AccessRightsDisplay = 'Read'
                AccessControlType   = 'Allow'
                NativeAce           = 'not-for-default-display'
            }
            $rule.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.CertificatePrivateKeyAccessRule'
            )
            $rule | Format-Table | Out-String -Width 240
        } -ArgumentList @(
            (Join-Path $script:repositoryRoot 'source\WindowsAccessControl.Format.ps1xml')
            $Account
            $orphanSid
        ) | Receive-Job -Wait -AutoRemoveJob

        $rendered | Should -Match '(?m)^Key\s+Scope\s+Account\s+Rights\s+Type\s*$'
        $rendered | Should -Match ([regex]::Escape($ExpectedIdentity))
        $rendered | Should -Match 'WacDisplayKey\s+Machine'
        $rendered | Should -Match 'Read\s+Allow'
        $rendered | Should -Not -Match 'not-for-default-display|NativeAce'
        if ($Account) {
            $rendered | Should -Not -Match ([regex]::Escape($orphanSid))
        }
    }

    It 'Should index every architecture decision record' {
        $decisionIndex = Get-Content -LiteralPath (
            Join-Path $script:decisionRoot 'README.md'
        ) -Raw
        $decisions = @(Get-ChildItem -LiteralPath $script:decisionRoot -File |
            Where-Object Name -Match '^\d{4}-.+\.md$')

        $decisions | Should -Not -BeNullOrEmpty
        foreach ($decision in $decisions) {
            $decisionIndex | Should -Match ([regex]::Escape($decision.Name))
            $header = Get-Content -LiteralPath $decision.FullName -TotalCount 8
            $header -join "`n" | Should -Match '- Status: (Proposed|Accepted|Superseded)'
        }
    }

    It 'Should explicitly defer remote and combined effective-access claims' {
        $decisionName = '0017-defer-remote-and-combined-effective-access.md'
        $decisionPath = Join-Path $script:decisionRoot $decisionName
        $decisionIndex = Get-Content -LiteralPath (
            Join-Path $script:decisionRoot 'README.md'
        ) -Raw
        $openIssues = Get-Content -LiteralPath (
            Join-Path $script:specRoot 'open-issues.md'
        ) -Raw
        $securityContract = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0004-security-and-persistence.md'
        ) -Raw

        $decisionPath | Should -Exist
        $decisionIndex | Should -Match ([regex]::Escape($decisionName))
        $openIssues | Should -Not -Match '(?m)^## OI-4:'
        $securityContract | Should -Match 'Remote and combined effective-access evaluation is unsupported'
    }

    It 'Should state the directory concurrency contract rather than imply a staleness gate' {
        $multiController = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0016-active-directory-multi-controller-behavior.md'
        ) -Raw

        $multiController | Should -Match 'No Active Directory command offers'
        $multiController | Should -Match 'one directory attribute'
        $multiController | Should -Match '\| Concurrent writers \|'
    }

    It 'Should split delivered enterprise increments into focused follow-up issues' {
        $openIssues = Get-Content -LiteralPath (
            Join-Path $script:specRoot 'open-issues.md'
        ) -Raw
        $editingContract = Get-Content -LiteralPath (
            Join-Path $script:specRoot '0007-in-memory-descriptor-mutation.md'
        ) -Raw
        $labInventory = Get-Content -LiteralPath (
            Join-Path $script:repositoryRoot 'docs\domain-lab-inventory.md'
        ) -Raw
        $decisionName = '0018-use-local-task-and-software-key-authority.md'
        $decisionPath = Join-Path $script:decisionRoot $decisionName
        $decisionIndex = Get-Content -LiteralPath (
            Join-Path $script:decisionRoot 'README.md'
        ) -Raw

        foreach ($closedIssue in 5, 6, 8, 9, 10, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31) {
            $openIssues | Should -Not -Match "(?m)^## OI-$closedIssue`:"
        }
        $coverageDecisionName = '0027-assert-coverage-over-executable-scope.md'
        Join-Path $script:decisionRoot $coverageDecisionName | Should -Exist
        $decisionIndex | Should -Match ([regex]::Escape($coverageDecisionName))
        $openIssues | Should -Not -Match '(?m)^## OI-12:'
        $openIssues | Should -Not -Match '(?m)^## OI-15:'
        $editingContract | Should -Match '(?m)^Status: Accepted\.'
        $labInventory | Should -Match '(?m)^Status: Verified'
        $labInventory | Should -Match 'Production network route isolation \| Verified'
        $decisionPath | Should -Exist
        $decisionIndex | Should -Match ([regex]::Escape($decisionName))
    }
}
