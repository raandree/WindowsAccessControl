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
            $heading -join "`n" | Should -Match 'Status: (Draft|Accepted|Superseded)'
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

        foreach ($closedIssue in 5, 6, 8, 9, 10, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 25, 26) {
            $openIssues | Should -Not -Match "(?m)^## OI-$closedIssue`:"
        }
        foreach ($focusedIssue in 23, 24, 27) {
            $openIssues | Should -Match "(?m)^## OI-$focusedIssue`:"
        }
        $openIssues | Should -Not -Match '(?m)^## OI-12:'
        $openIssues | Should -Not -Match '(?m)^## OI-15:'
        $editingContract | Should -Match '(?m)^Status: Accepted\.'
        $labInventory | Should -Match '(?m)^Status: Verified'
        $labInventory | Should -Match 'Production network route isolation \| Verified'
        $decisionPath | Should -Exist
        $decisionIndex | Should -Match ([regex]::Escape($decisionName))
    }
}
