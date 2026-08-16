# Reparse point and link behavior (FR-30, ADR 0030, ADR 0031). Every fixture is
# created and removed inside the test; no operating-system junction is touched.
BeforeAll {
    $script:moduleManifestPath = (
        Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
    ).FullName
    Import-Module -Name $script:moduleManifestPath -Force -ErrorAction Stop

    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:symbolicLinkSkipReason = $null
    if (-not (Get-WindowsPrivilege | Where-Object Name -EQ 'SeCreateSymbolicLinkPrivilege')) {
        $developerMode = (
            Get-ItemProperty `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' `
                -Name 'AllowDevelopmentWithoutDevLicense' `
                -ErrorAction SilentlyContinue
        ).AllowDevelopmentWithoutDevLicense
        if ($developerMode -ne 1) {
            $script:symbolicLinkSkipReason =
                'The process token does not contain SeCreateSymbolicLinkPrivilege and Developer Mode is off.'
        }
    }

    # A link is removed as a link, never followed. Recursive removal of a
    # directory tree that contains one would delete through it, and a
    # self-referential junction would not terminate, so the fixtures live
    # outside TestDrive and are torn down link first.
    # A hosted build agent reports TEMP in its 8.3 short form, and the module
    # reports the expanded name, so the root is canonicalized before it is used.
    $tempRoot = (Get-Item -LiteralPath $env:TEMP).FullName
    $script:linkRoot = Join-Path -Path $tempRoot -ChildPath (
        'wac-links-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    )
    $null = New-Item -Path $script:linkRoot -ItemType Directory -Force
    $script:createdLinks = [System.Collections.Generic.List[string]]::new()

    function script:New-LinkFixture {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $root = Join-Path -Path $script:linkRoot -ChildPath $Name
        $target = Join-Path -Path $root -ChildPath 'target'
        $null = New-Item -Path $target -ItemType Directory -Force
        $file = Join-Path -Path $root -ChildPath 'file.txt'
        Set-Content -LiteralPath $file -Value 'reparse'

        [pscustomobject]@{
            Root   = $root
            Target = $target
            File   = $file
        }
    }

    function script:New-TrackedLink {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [ValidateSet('Junction', 'SymbolicLink', 'HardLink')]
            [string]$ItemType,

            [Parameter(Mandatory)]
            [string]$Target
        )

        $null = New-Item -Path $Path -ItemType $ItemType -Target $Target -ErrorAction Stop
        if ($ItemType -ne 'HardLink') {
            $script:createdLinks.Add($Path)
        }
        $Path
    }

    function script:Get-ExplicitRuleCount {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        @(Get-NTFSAccessRule -LiteralPath $Path -Account $script:currentSid -ExcludeInherited).Count
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
    foreach ($link in $script:createdLinks) {
        try {
            if ([System.IO.Directory]::Exists($link)) {
                [System.IO.Directory]::Delete($link, $false)
            } elseif ([System.IO.File]::Exists($link)) {
                [System.IO.File]::Delete($link)
            }
        } catch {
            Write-Warning "Could not remove link $link : $($_.Exception.Message)"
        }
    }
    if ($script:linkRoot -and (Test-Path -LiteralPath $script:linkRoot)) {
        Remove-Item -LiteralPath $script:linkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'NTFS reparse point and link behavior' -Tag 'Integration', 'WindowsOnly' {
    Context 'Junction' {
        It 'Should address the junction itself and leave the destination untouched' {
            $fixture = New-LinkFixture -Name 'junction-write'
            $junction = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'link') `
                -ItemType Junction `
                -Target $fixture.Target
            $addParameters = @{
                LiteralPath  = $junction
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            (Get-ExplicitRuleCount -Path $junction) | Should -Be 1
            (Get-ExplicitRuleCount -Path $fixture.Target) | Should -Be 0
        }

        It 'Should not report a change made on the destination through the junction' {
            $fixture = New-LinkFixture -Name 'junction-read'
            $junction = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'link') `
                -ItemType Junction `
                -Target $fixture.Target
            $addParameters = @{
                LiteralPath  = $fixture.Target
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            (Get-ExplicitRuleCount -Path $fixture.Target) | Should -Be 1
            (Get-ExplicitRuleCount -Path $junction) | Should -Be 0
        }

        It 'Should distinguish the junction descriptor from the destination descriptor' {
            $fixture = New-LinkFixture -Name 'junction-identity'
            $junction = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'link') `
                -ItemType Junction `
                -Target $fixture.Target
            $linkItem = Get-Item -LiteralPath $junction -Force
            $addParameters = @{
                LiteralPath  = $junction
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            ([int]$linkItem.Attributes -band
                [int][System.IO.FileAttributes]::ReparsePoint) | Should -Not -Be 0
            (Get-NTFSItemSecurityDescriptor -LiteralPath $junction).Sddl |
                Should -Not -Be (Get-NTFSItemSecurityDescriptor -LiteralPath $fixture.Target).Sddl
        }

        It 'Should agree with icacls on the junction descriptor' {
            $fixture = New-LinkFixture -Name 'junction-icacls'
            $junction = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'link') `
                -ItemType Junction `
                -Target $fixture.Target
            $addParameters = @{
                LiteralPath  = $junction
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            # icacls without /L reports the same list as icacls /L for a
            # junction, which is what the module reports too.
            $withoutLinkFlag = @(& icacls.exe $junction) -join "`n"
            $withLinkFlag = @(& icacls.exe $junction /L) -join "`n"
            $withoutLinkFlag | Should -Be $withLinkFlag
        }

        It 'Should report each supplied path once for a junction and its destination' {
            $fixture = New-LinkFixture -Name 'junction-batch'
            $junction = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'link') `
                -ItemType Junction `
                -Target $fixture.Target

            $descriptors = @(
                Get-NTFSItemSecurityDescriptor -LiteralPath @($junction, $fixture.Target, $junction)
            )

            @($descriptors.Path | Sort-Object) |
                Should -Be @(@($junction, $fixture.Target) | Sort-Object)
        }
    }

    Context 'Self-referential junction' {
        It 'Should terminate on a junction that points at its own parent' {
            $fixture = New-LinkFixture -Name 'junction-loop'
            $null = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'loop') `
                -ItemType Junction `
                -Target $fixture.Root

            $job = Start-Job -ScriptBlock {
                param($ManifestPath, $Root)

                Import-Module -Name $ManifestPath -Force -ErrorAction Stop
                @(Get-NTFSAccessRule -Path (Join-Path $Root '*')).Count
            } -ArgumentList $script:moduleManifestPath, $fixture.Root

            try {
                $completed = Wait-Job -Job $job -Timeout 120
                $completed | Should -Not -BeNullOrEmpty -Because 'wildcard expansion must terminate'
                $ruleCount = Receive-Job -Job $job
                $ruleCount | Should -BeGreaterThan 0
            } finally {
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should expand a wildcard exactly one level' {
            $fixture = New-LinkFixture -Name 'junction-one-level'
            $loop = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'loop') `
                -ItemType Junction `
                -Target $fixture.Root
            $null = New-Item -Path (Join-Path $fixture.Target 'grandchild') -ItemType Directory -Force

            $descriptors = @(Get-NTFSItemSecurityDescriptor -Path (Join-Path $fixture.Root '*'))

            @($descriptors.Path | Sort-Object) |
                Should -Be @(@($fixture.File, $loop, $fixture.Target) | Sort-Object)
        }
    }

    Context 'Hard link' {
        It 'Should share one descriptor between both names' {
            $fixture = New-LinkFixture -Name 'hard-link'
            $hardLink = New-TrackedLink `
                -Path (Join-Path $fixture.Root 'hard.txt') `
                -ItemType HardLink `
                -Target $fixture.File
            $addParameters = @{
                LiteralPath  = $hardLink
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                Confirm      = $false
            }

            $before = (Get-NTFSItemSecurityDescriptor -LiteralPath $fixture.File).Sddl
            Add-NTFSAccessRule @addParameters
            $after = (Get-NTFSItemSecurityDescriptor -LiteralPath $fixture.File).Sddl

            $after | Should -Not -Be $before
            $after | Should -Be (Get-NTFSItemSecurityDescriptor -LiteralPath $hardLink).Sddl
            (Get-ExplicitRuleCount -Path $fixture.File) | Should -Be 1
        }
    }

    Context 'Symbolic link' -Tag 'RequiresElevation' {
        It 'Should address the <Label> symbolic link itself' -ForEach @(
            @{ Label = 'directory'; IsContainer = $true }
            @{ Label = 'file'; IsContainer = $false }
        ) {
            if ($script:symbolicLinkSkipReason) {
                Set-ItResult -Skipped -Because $script:symbolicLinkSkipReason
                return
            }
            $fixture = New-LinkFixture -Name ('symlink-' + $Label)
            $destination = if ($IsContainer) { $fixture.Target } else { $fixture.File }
            $link = New-TrackedLink `
                -Path (Join-Path $fixture.Root ('link-' + $Label)) `
                -ItemType SymbolicLink `
                -Target $destination
            $addParameters = @{
                LiteralPath  = $link
                Account      = $script:currentSid
                AccessRights = 'FullControl'
                Confirm      = $false
            }
            if ($IsContainer) {
                $addParameters.AppliesTo = 'ThisFolderOnly'
            }

            Add-NTFSAccessRule @addParameters

            (Get-ExplicitRuleCount -Path $link) | Should -Be 1
            (Get-ExplicitRuleCount -Path $destination) | Should -Be 0
        }
    }

    Context 'Volume mount point' {
        It 'Should not cross into a mounted volume' {
            $mountPoints = @(
                Get-Partition -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.AccessPaths } |
                    Where-Object { $_ -match '^[A-Za-z]:\\.+' }
            )
            if ($mountPoints.Count -eq 0) {
                Set-ItResult -Skipped -Because (
                    'No volume mount point exists on this host and creating one would repartition it.'
                )
                return
            }

            $mountPoint = $mountPoints[0].TrimEnd('\')
            $parent = Split-Path -Path $mountPoint -Parent
            $descriptors = @(Get-NTFSItemSecurityDescriptor -Path (Join-Path $parent '*'))

            # One level only: the mount point itself is reported, nothing inside
            # the mounted volume is.
            @($descriptors.Path) | Should -Contain $mountPoint
            @($descriptors.Path | Where-Object { $_ -like "$mountPoint\*" }) | Should -BeNullOrEmpty
        }
    }
}
