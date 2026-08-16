# NTFS path and name input matrix (FR-16, FR-29, ADR 0029). Every case asserts a
# deterministic outcome on a real item; an edition difference is asserted, not
# skipped.
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:isCoreEdition = $PSVersionTable.PSEdition -eq 'Core'
    $script:longPathsEnabled = [int](
        Get-ItemProperty `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
            -Name 'LongPathsEnabled' `
            -ErrorAction SilentlyContinue
    ).LongPathsEnabled
    # PowerShell 7 opts into long paths itself. Windows PowerShell only reaches a
    # target past MAX_PATH when the machine policy is on.
    $script:longPathReadable = $script:isCoreEdition -or $script:longPathsEnabled -eq 1

    # A name that only exists untrimmed, and a path past MAX_PATH, cannot be
    # removed through a normalized path, so these fixtures stay out of TestDrive
    # and are deleted through the device namespace.
    # A hosted build agent reports TEMP in its 8.3 short form, and the module
    # reports the expanded name, so the root is canonicalized before it is used.
    $tempRoot = (Get-Item -LiteralPath $env:TEMP).FullName
    $script:hostileRoot = Join-Path -Path $tempRoot -ChildPath (
        'wac-pathmatrix-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    )
    $null = New-Item -Path $script:hostileRoot -ItemType Directory -Force

    function script:New-MatrixDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $path = Join-Path -Path $TestDrive -ChildPath $Name
        $null = New-Item -Path $path -ItemType Directory -Force
        $path
    }

    function script:New-MatrixFile {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $path = Join-Path -Path $TestDrive -ChildPath $Name
        Set-Content -LiteralPath $path -Value 'matrix'
        $path
    }

    function script:New-HostileDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        # Only the device namespace can create a name Windows would otherwise
        # trim, so the fixture is built outside the module on purpose.
        $path = Join-Path -Path $script:hostileRoot -ChildPath $Name
        $null = [System.IO.Directory]::CreateDirectory("\\?\$path")
        $path
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
    if ($script:hostileRoot) {
        try {
            [System.IO.Directory]::Delete("\\?\$script:hostileRoot", $true)
        } catch {
            Write-Warning "Could not remove $script:hostileRoot : $($_.Exception.Message)"
        }
    }
}

Describe 'NTFS path input matrix' -Tag 'Integration', 'WindowsOnly' {
    Context 'Names Windows normalizes away' {
        It 'Should resolve a trailing <Label> to the trimmed name it actually created' -ForEach @(
            @{ Label = 'space'; Suffix = ' '; Stem = 'trimmed-space' }
            @{ Label = 'period'; Suffix = '.'; Stem = 'trimmed-period' }
        ) {
            $requested = Join-Path -Path $TestDrive -ChildPath ($Stem + $Suffix)
            $null = New-Item -Path $requested -ItemType Directory -Force

            $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $requested

            $descriptor.Path | Should -Be (Join-Path -Path $TestDrive -ChildPath $Stem)
            @(Get-ChildItem -LiteralPath $TestDrive -Directory |
                Where-Object Name -EQ $Stem) | Should -HaveCount 1
        }

        It 'Should refuse a name that only exists with a trailing <Label>' -ForEach @(
            @{ Label = 'space'; Suffix = ' '; Stem = 'untrimmed-space' }
            @{ Label = 'period'; Suffix = '.'; Stem = 'untrimmed-period' }
        ) {
            $path = New-HostileDirectory -Name ($Stem + $Suffix)

            { Get-NTFSItemSecurityDescriptor -LiteralPath $path -ErrorAction Stop } |
                Should -Throw
            { Get-NTFSAccessRule -LiteralPath $path -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Names that begin with a shell-significant character' {
        It 'Should read and write a name beginning with <Character>' -ForEach @(
            @{ Character = '$' }
            @{ Character = '-' }
            @{ Character = '+' }
            @{ Character = '#' }
            @{ Character = '{' }
            @{ Character = ',' }
        ) {
            $path = New-MatrixFile -Name ($Character + 'leading.txt')
            $addParameters = @{
                LiteralPath  = $path
                Account      = $script:currentSid
                AccessRights = 'Read'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters
            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:currentSid -ExcludeInherited)
            $owner = Get-NTFSItemOwner -LiteralPath $path

            $rules | Should -Not -BeNullOrEmpty
            $rules[0].Path | Should -Be $path
            $owner.Path | Should -Be $path
        }
    }

    Context 'Wildcard and literal semantics' {
        It 'Should treat a bracketed name as literal for LiteralPath' {
            $path = New-MatrixFile -Name 'bracket[1].txt'

            $rules = @(Get-NTFSAccessRule -LiteralPath $path)

            $rules | Should -Not -BeNullOrEmpty
            @($rules.Path | Sort-Object -Unique) | Should -Be @($path)
        }

        It 'Should let Path expand the bracket as the provider does' {
            $null = New-MatrixFile -Name 'bracketpath[1].txt'
            $decoyPath = New-MatrixFile -Name 'bracketpath1.txt'

            $rules = @(Get-NTFSAccessRule -Path (Join-Path $TestDrive 'bracketpath[1].txt'))

            # The provider reads [1] as a character class, so the literal name is
            # never matched and the decoy is.
            @($rules.Path | Sort-Object -Unique) | Should -Be @($decoyPath)
        }

        It 'Should expand a question mark and an asterisk through Path' {
            $first = New-MatrixFile -Name 'wild1.txt'
            $second = New-MatrixFile -Name 'wild2.txt'

            $questionMark = @(Get-NTFSAccessRule -Path (Join-Path $TestDrive 'wild?.txt'))
            $asterisk = @(Get-NTFSAccessRule -Path (Join-Path $TestDrive 'wild*.txt'))

            @($questionMark.Path | Sort-Object -Unique) | Should -Be @($first, $second)
            @($asterisk.Path | Sort-Object -Unique) | Should -Be @($first, $second)
        }

        It 'Should not expand a wildcard supplied through LiteralPath' {
            $null = New-MatrixFile -Name 'literalwild1.txt'
            $literalPath = Join-Path $TestDrive 'literalwild?.txt'

            if ($script:isCoreEdition) {
                { Get-NTFSAccessRule -LiteralPath $literalPath -ErrorAction Stop } |
                    Should -Throw
            } else {
                # Windows PowerShell resolves a literal path through the wildcard
                # machinery, so a pattern that matches nothing is an empty result
                # rather than a missing path. Neither edition expands it.
                @(Get-NTFSAccessRule -LiteralPath $literalPath) | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Drive specifications' {
        It 'Should refuse a bare drive specification' {
            $errorRecord = $null
            try {
                Get-NTFSItemSecurityDescriptor -LiteralPath 'C:' -ErrorAction Stop
            } catch {
                $errorRecord = $_
            }

            $errorRecord | Should -Not -BeNullOrEmpty
            $errorRecord.FullyQualifiedErrorId |
                Should -BeLike '*AmbiguousDriveSpecification*'
            $errorRecord.Exception.Message |
                Should -BeLike "*resolves to the current location of that drive*"
        }

        It 'Should report the volume root directory for a drive root' {
            $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\'

            $descriptor.Path | Should -Be 'C:\'
            $descriptor.Sddl | Should -Be (Get-Acl -LiteralPath 'C:\').Sddl
        }

        It 'Should resolve a drive-relative child against that drive' {
            $child = New-MatrixDirectory -Name 'drive-relative'
            $driveRelative = $TestDrive.Substring(0, 2) + 'drive-relative'

            Push-Location -LiteralPath $TestDrive
            try {
                $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $driveRelative
            } finally {
                Pop-Location
            }

            $descriptor.Path | Should -Be $child
        }
    }

    Context 'Relative paths' {
        It 'Should resolve <Label>' -ForEach @(
            @{ Label = 'the current directory'; Relative = '.' }
            @{ Label = 'the parent directory'; Relative = '..' }
            @{ Label = 'a relative child'; Relative = 'relative-child' }
        ) {
            $child = New-MatrixDirectory -Name 'relative-child'
            $expected = switch ($Relative) {
                '.' { [string](Get-Item -LiteralPath $TestDrive).FullName }
                '..' { [string](Get-Item -LiteralPath $TestDrive).Parent.FullName }
                default { $child }
            }

            Push-Location -LiteralPath $TestDrive
            try {
                $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $Relative
            } finally {
                Pop-Location
            }

            $descriptor.Path | Should -Be $expected
        }
    }

    Context 'File system objects bound positionally' {
        It 'Should bind a <Label> to the same target as its FullName' -ForEach @(
            @{ Label = 'DirectoryInfo'; IsContainer = $true }
            @{ Label = 'FileInfo'; IsContainer = $false }
        ) {
            $path = if ($IsContainer) {
                New-MatrixDirectory -Name 'positional-directory'
            } else {
                New-MatrixFile -Name 'positional-file.txt'
            }
            $item = Get-Item -LiteralPath $path

            $fromObject = @(Get-NTFSAccessRule $item)
            $fromString = @(Get-NTFSAccessRule $item.FullName)

            $fromObject.Count | Should -Be $fromString.Count
            @($fromObject.Path | Sort-Object -Unique) | Should -Be @($path)
        }
    }

    Context 'Length limits' {
        It 'Should report the edition outcome for a path longer than 260 characters' {
            $parent = New-HostileDirectory -Name ('a' * 200)
            $deep = Join-Path -Path $parent -ChildPath ('b' * 100)
            $null = [System.IO.Directory]::CreateDirectory("\\?\$deep")
            $deep.Length | Should -BeGreaterThan 260

            if ($script:longPathReadable) {
                $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $deep
                $descriptor.Path | Should -Be $deep
            } else {
                { Get-NTFSItemSecurityDescriptor -LiteralPath $deep -ErrorAction Stop } |
                    Should -Throw
            }
        }

        It 'Should accept a single component of exactly 255 characters' {
            $path = New-HostileDirectory -Name ('c' * 255)

            if ($script:longPathReadable -or $path.Length -lt 248) {
                $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $path
                $descriptor.Path | Should -Be $path
            } else {
                { Get-NTFSItemSecurityDescriptor -LiteralPath $path -ErrorAction Stop } |
                    Should -Throw
            }
        }

        It 'Should not be able to create a component of 256 characters' {
            {
                [System.IO.Directory]::CreateDirectory(
                    "\\?\" + (Join-Path -Path $script:hostileRoot -ChildPath ('d' * 256))
                )
            } | Should -Throw
        }
    }

    Context 'Reserved device names' {
        It 'Should refuse the reserved name <Name>' -ForEach @(
            @{ Name = 'NUL' }
            @{ Name = 'NUL.txt' }
            @{ Name = 'COM1' }
        ) {
            $path = Join-Path -Path $TestDrive -ChildPath $Name

            { Get-NTFSItemSecurityDescriptor -LiteralPath $path -ErrorAction Stop } |
                Should -Throw
            { Get-NTFSAccessRule -LiteralPath $Name -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Spelling variants of the same target' {
        It 'Should report the same descriptor for a mixed-case path' {
            $path = New-MatrixDirectory -Name 'CaseVariant'

            $canonical = Get-NTFSItemSecurityDescriptor -LiteralPath $path
            $upperCase = Get-NTFSItemSecurityDescriptor -LiteralPath $path.ToUpperInvariant()

            $upperCase.Sddl | Should -Be $canonical.Sddl
        }

        It 'Should normalize forward slash separators' {
            $path = New-MatrixDirectory -Name 'SlashVariant'

            $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $path.Replace('\', '/')

            $descriptor.Path | Should -Be $path
        }
    }

    Context 'Universal naming convention targets' {
        It 'Should report the same descriptor through the administrative share' {
            $localPath = New-MatrixDirectory -Name 'unc-target'
            $administrativeShare = '\\{0}\{1}$' -f $env:COMPUTERNAME, $localPath.Substring(0, 1)
            if (-not (Test-Path -LiteralPath $administrativeShare)) {
                Set-ItResult -Skipped -Because "The administrative share $administrativeShare is not reachable."
                return
            }
            $uncPath = $administrativeShare + $localPath.Substring(2)

            $local = Get-NTFSItemSecurityDescriptor -LiteralPath $localPath
            $remote = Get-NTFSItemSecurityDescriptor -LiteralPath $uncPath

            $remote.Sddl | Should -Be $local.Sddl
            $remote.Path | Should -Be $uncPath
        }
    }

    Context 'Device namespace targets' {
        It 'Should refuse <Label>' -ForEach @(
            @{ Label = 'an extended-length local path'; Target = '\\?\C:\Windows' }
            @{ Label = 'an extended-length universal naming convention path'; Target = '\\?\UNC\server\share' }
            @{ Label = 'a device path'; Target = '\\.\C:' }
        ) {
            $errorRecord = $null
            try {
                Get-NTFSItemSecurityDescriptor -LiteralPath $Target -ErrorAction Stop
            } catch {
                $errorRecord = $_
            }

            $errorRecord | Should -Not -BeNullOrEmpty
            $errorRecord.FullyQualifiedErrorId |
                Should -BeLike '*DeviceNamespacePathNotSupported*'
            $errorRecord.Exception.Message | Should -BeLike '*Win32 device namespace*'
        }

        It 'Should refuse a device-namespace path on the write side as well' {
            $addParameters = @{
                LiteralPath  = '\\?\C:\Windows'
                Account      = $script:currentSid
                AccessRights = 'Read'
                Confirm      = $false
                ErrorAction  = 'Stop'
            }

            { Add-NTFSAccessRule @addParameters } | Should -Throw
            { Get-NTFSItemOwner -LiteralPath '\\?\C:\Windows' -ErrorAction Stop } | Should -Throw
        }
    }
}
