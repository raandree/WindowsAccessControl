BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\Lab\WindowsAccessControl.LabRunnerOwnership.ps1')

    function New-TestRunnerMarker {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'This test helper writes only below TestDrive.'
        )]
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$Directory)

        $marker = Get-WindowsAccessControlLabRunnerMarker
        [IO.File]::WriteAllText(
            (Join-Path $Directory $marker.FileName),
            $marker.Text,
            [Text.UTF8Encoding]::new($false)
        )
    }
}

Describe 'Lab runner payload root rules' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        # Cases that test another rule still pass a real protected list, because
        # an empty list is itself refused.
        $script:protectedRoot = Join-Path $TestDrive 'Protected'
        $null = New-Item -Path $script:protectedRoot -ItemType Directory -Force
    }

    It 'Should reject a payload root that is not an absolute local path: <Case>' -ForEach @(
        @{ Case = 'empty'; Path = '' }
        @{ Case = 'relative'; Path = 'WacRepo' }
        @{ Case = 'drive-relative'; Path = 'C:WacRepo' }
        @{ Case = 'rooted without a drive'; Path = '\WacRepo' }
        @{ Case = 'UNC'; Path = '\\server\share\WacRepo' }
        @{ Case = 'device'; Path = '\\?\C:\WacRepo' }
        @{ Case = 'provider-qualified'; Path = 'Microsoft.PowerShell.Core\FileSystem::C:\WacRepo' }
        @{ Case = 'registry'; Path = 'HKLM:\SOFTWARE\WacRepo' }
    ) {
        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $Path -ProtectedPath @($script:protectedRoot) } |
            Should -Throw '*is not an absolute local path*'
    }

    It 'Should reject a payload root that contains <Case>' -ForEach @(
        @{ Case = 'a wildcard'; Path = 'C:\Wac*' }
        @{ Case = 'a question mark'; Path = 'C:\Wac?Repo' }
        @{ Case = 'an opening bracket'; Path = 'C:\Wac[1' }
        @{ Case = 'a bracket pair'; Path = 'C:\Wac[1]' }
        @{ Case = 'a pipe'; Path = 'C:\Wac|Repo' }
        @{ Case = 'an alternate data stream'; Path = 'C:\WacRepo:stream' }
    ) {
        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $Path -ProtectedPath @($script:protectedRoot) } |
            Should -Throw '*contains a character that a payload root must not use*'
    }

    It 'Should reject the drive root <Path>' -ForEach @(
        @{ Path = 'C:\' }
        @{ Path = 'C:/' }
        @{ Path = 'C:\WacRepo\..' }
    ) {
        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $Path -ProtectedPath @($script:protectedRoot) } |
            Should -Throw '*is a drive root*'
    }

    It 'Should reject a payload root on a drive letter that is not a local fixed drive' {
        # A unit test cannot attach a network or removable drive, so an
        # unassigned letter stands in for every drive type other than Fixed.
        $usedLetters = @([IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
        $unusedLetter = [char[]]([int][char]'D'..[int][char]'Z') |
            Where-Object { [string]$_ -notin $usedLetters } |
            Select-Object -Last 1
        $unusedLetter | Should -Not -BeNullOrEmpty

        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path "$($unusedLetter):\WacRepo" -ProtectedPath @($script:protectedRoot) } |
            Should -Throw '*is not on a local fixed drive*'
    }

    It 'Should refuse a protected-directory list <Case> rather than skip the check' -ForEach @(
        @{ Case = 'that is empty'; ProtectedList = @() }
        @{ Case = 'with a blank entry'; ProtectedList = @(' ') }
    ) {
        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path 'C:\WacRepo' -ProtectedPath $ProtectedList } |
            Should -Throw "*ProtectedPath*"
    }

    It 'Should reject <Case> of a protected directory' -ForEach @(
        @{ Case = 'the directory itself'; Child = '' }
        @{ Case = 'a child'; Child = 'WacRepo' }
        @{ Case = 'a differently cased descendant'; Child = 'WACREPO\Deeper' }
        @{ Case = 'a path that climbs back into it'; Child = 'WacRepo\..\..\Protected\WacRepo' }
    ) {
        $candidate = if ($Child) { Join-Path $script:protectedRoot $Child } else { $script:protectedRoot }

        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $candidate -ProtectedPath @($script:protectedRoot) } |
            Should -Throw "*lies under the protected directory*"
    }

    It 'Should accept a sibling whose name only starts with a protected directory name' {
        $sibling = "$($script:protectedRoot)Sibling\WacRepo"

        $result = Assert-WindowsAccessControlLabRunnerPayloadPath -Path $sibling -ProtectedPath @("$($script:protectedRoot)\")

        $result | Should -BeExactly ([IO.Path]::GetFullPath($sibling))
    }

    It 'Should return the normalized payload root for an absent directory' {
        $candidate = Join-Path $TestDrive 'Accepted\Nested\..\WacRepo\'

        $result = Assert-WindowsAccessControlLabRunnerPayloadPath -Path ($candidate -replace '\\', '/') -ProtectedPath @($script:protectedRoot)

        $result | Should -BeExactly ([IO.Path]::GetFullPath((Join-Path $TestDrive 'Accepted\WacRepo')))
    }

    It 'Should reject a payload root that is, or lies under, a junction' {
        $target = Join-Path $TestDrive 'JunctionTarget'
        $link = Join-Path $TestDrive 'JunctionLink'
        $null = New-Item -Path $target -ItemType Directory -Force
        $null = New-Item -Path $link -ItemType Junction -Target $target
        try {
            { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $link -ProtectedPath @($script:protectedRoot) } |
                Should -Throw '*junction or symbolic link*'
            { Assert-WindowsAccessControlLabRunnerPayloadPath -Path (Join-Path $link 'WacRepo') -ProtectedPath @($script:protectedRoot) } |
                Should -Throw '*junction or symbolic link*'
        }
        finally {
            [IO.Directory]::Delete($link)
        }
    }

    It 'Should name the machine that evaluated the payload root' {
        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path 'WacRepo' -ProtectedPath @($script:protectedRoot) } |
            Should -Throw "*on '$env:COMPUTERNAME'*"
    }
}

Describe 'Lab runner protected directories of the evaluating machine' -Tag 'Unit', 'WindowsOnly' {
    It 'Should protect the <Name> of this machine' -ForEach @(
        @{ Name = 'Windows directory'; Directory = [Environment]::GetFolderPath('Windows') }
        @{ Name = 'Program Files directory'; Directory = [Environment]::GetFolderPath('ProgramFiles') }
        @{ Name = 'ProgramData directory'; Directory = [Environment]::GetFolderPath('CommonApplicationData') }
        @{
            Name = 'user profile root'
            Directory = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory).ProfilesDirectory
        }
    ) {
        $protected = @(Get-WindowsAccessControlLabRunnerProtectedPath)

        $protected | Should -Contain ([IO.Path]::GetFullPath($Directory).TrimEnd('\'))
    }

    It 'Should reject a payload root under <Name> without an explicit protected list' -ForEach @(
        @{ Name = 'the Windows directory'; Directory = $env:SystemRoot }
        @{ Name = 'Program Files'; Directory = $env:ProgramFiles }
        @{ Name = 'Program Files (x86)'; Directory = ${env:ProgramFiles(x86)} }
        @{ Name = 'ProgramData'; Directory = $env:ProgramData }
        @{ Name = 'the current user profile'; Directory = $env:USERPROFILE }
    ) {
        $candidate = Join-Path $Directory 'WindowsAccessControlLabRunnerUnitTest'

        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path $candidate } |
            Should -Throw '*lies under the protected directory*'
    }

    It 'Should reject Program Files by its 8.3 short name where the volume records one' {
        $fileSystem = New-Object -ComObject Scripting.FileSystemObject
        try {
            $shortProgramFiles = $fileSystem.GetFolder($env:ProgramFiles).ShortPath
        }
        finally {
            $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($fileSystem)
        }
        $shortProgramFiles | Should -Not -BeNullOrEmpty
        if ($shortProgramFiles -eq $env:ProgramFiles) {
            # Without a recorded short name there is no alias to test, and the
            # long-name case is already covered above.
            Set-ItResult -Skipped -Because 'the system volume records no 8.3 name for Program Files'
            return
        }

        { Assert-WindowsAccessControlLabRunnerPayloadPath -Path (Join-Path $shortProgramFiles 'WacRepo') } |
            Should -Throw '*lies under the protected directory*'
    }
}

Describe 'Lab runner directory ownership' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    It 'Should name a fixed marker file that the runner documentation can refer to' {
        $marker = Get-WindowsAccessControlLabRunnerMarker

        $marker.FileName | Should -BeExactly '.windows-access-control-lab-runner'
        $marker.Text | Should -Not -BeNullOrEmpty
    }

    It 'Should report an absent directory as absent' {
        (Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory).State |
            Should -BeExactly 'Absent'
    }

    It 'Should report a marked directory as owned' {
        $null = New-Item -Path $script:directory -ItemType Directory
        New-TestRunnerMarker -Directory $script:directory

        (Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory).State |
            Should -BeExactly 'Owned'
    }

    It 'Should report <Case> as unowned' -ForEach @(
        @{ Case = 'a directory without a marker'; MarkerText = $null; Reason = '*carries no*marker*' }
        @{ Case = 'a directory whose marker holds other text'; MarkerText = 'Managed by someone else.'; Reason = '*does not hold the runner*' }
    ) {
        $null = New-Item -Path $script:directory -ItemType Directory
        if ($MarkerText) {
            $markerFile = Join-Path $script:directory (Get-WindowsAccessControlLabRunnerMarker).FileName
            Set-Content -LiteralPath $markerFile -Value $MarkerText -NoNewline
        }

        $ownership = Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory

        $ownership.State | Should -BeExactly 'Unowned'
        $ownership.Reason | Should -BeLike $Reason
    }

    It 'Should report a file at the path as unowned' {
        Set-Content -LiteralPath $script:directory -Value 'not a directory' -NoNewline

        $ownership = Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory

        $ownership.State | Should -BeExactly 'Unowned'
        $ownership.Reason | Should -BeLike '*not a directory*'
    }

    It 'Should report a junction to a marked directory as unowned' {
        $target = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $target -ItemType Directory
        New-TestRunnerMarker -Directory $target
        $null = New-Item -Path $script:directory -ItemType Junction -Target $target
        try {
            $ownership = Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory

            $ownership.State | Should -BeExactly 'Unowned'
            $ownership.Reason | Should -BeLike '*junction or symbolic link*'
        }
        finally {
            [IO.Directory]::Delete($script:directory)
        }
    }

    It 'Should report a marked directory that contains a junction as unowned' {
        $outside = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $outside -ItemType Directory
        $null = New-Item -Path (Join-Path $script:directory 'tests\nested') -ItemType Directory -Force
        New-TestRunnerMarker -Directory $script:directory
        $link = Join-Path $script:directory 'tests\nested\outside'
        $null = New-Item -Path $link -ItemType Junction -Target $outside
        try {
            $ownership = Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory

            $ownership.State | Should -BeExactly 'Unowned'
            $ownership.Reason | Should -BeLike "*contains the junction or symbolic link '$link'*"
        }
        finally {
            [IO.Directory]::Delete($link)
        }
    }
}

Describe 'Lab runner directory reset' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:resolution = 'Inspect it, then remove it yourself.'
    }

    It 'Should refuse an unmarked directory before deleting anything and name the path and the resolution' {
        $null = New-Item -Path $script:directory -ItemType Directory
        $sentinel = Join-Path $script:directory 'operator-data.txt'
        Set-Content -LiteralPath $sentinel -Value 'not created by the runner' -NoNewline

        { Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution } |
            Should -Throw "*Refusing to replace '$($script:directory)'*carries no*marker*$($script:resolution)*"

        Get-Content -LiteralPath $sentinel -Raw | Should -BeExactly 'not created by the runner'
        Join-Path $script:directory (Get-WindowsAccessControlLabRunnerMarker).FileName | Should -Not -Exist
    }

    It 'Should refuse a file at the path and keep it' {
        Set-Content -LiteralPath $script:directory -Value 'operator file' -NoNewline

        { Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution } |
            Should -Throw '*not a directory*'

        Get-Content -LiteralPath $script:directory -Raw | Should -BeExactly 'operator file'
    }

    It 'Should refuse a marked directory that contains a junction and keep what the junction reaches' {
        $outside = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $outside -ItemType Directory
        $outsideFile = Join-Path $outside 'not-runner-owned.txt'
        Set-Content -LiteralPath $outsideFile -Value 'outside the runner tree' -NoNewline
        $null = New-Item -Path $script:directory -ItemType Directory
        New-TestRunnerMarker -Directory $script:directory
        $link = Join-Path $script:directory 'outside'
        $null = New-Item -Path $link -ItemType Junction -Target $outside
        try {
            { Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution } |
                Should -Throw "*Refusing to replace '$($script:directory)'*contains the junction or symbolic link*"

            Get-Content -LiteralPath $outsideFile -Raw | Should -BeExactly 'outside the runner tree'
            $link | Should -Exist
        }
        finally {
            [IO.Directory]::Delete($link)
        }
    }

    It 'Should create an absent directory and write the marker on creation' {
        Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution

        $marker = Get-WindowsAccessControlLabRunnerMarker
        $markerFile = Join-Path $script:directory $marker.FileName
        $markerFile | Should -Exist
        [IO.File]::ReadAllText($markerFile) | Should -BeExactly $marker.Text
        @(Get-ChildItem -LiteralPath $script:directory -Force).Name | Should -Be @($marker.FileName)
        (Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:directory).State | Should -BeExactly 'Owned'
    }

    It 'Should replace a marked directory with an empty marked directory' {
        $null = New-Item -Path (Join-Path $script:directory 'stale\nested') -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:directory 'stale\nested\old.txt') -Value 'old payload'
        New-TestRunnerMarker -Directory $script:directory

        Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution

        @(Get-ChildItem -LiteralPath $script:directory -Force).Name |
            Should -Be @((Get-WindowsAccessControlLabRunnerMarker).FileName)
    }

    It 'Should remove the directory it created when the marker cannot be written' {
        Mock Get-WindowsAccessControlLabRunnerMarker {
            [pscustomobject]@{ FileName = 'invalid|marker'; Text = 'unused' }
        }

        { Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution } |
            Should -Throw

        $script:directory | Should -Not -Exist
    }

    It 'Should change nothing under WhatIf' {
        $null = New-Item -Path $script:directory -ItemType Directory
        New-TestRunnerMarker -Directory $script:directory
        $kept = Join-Path $script:directory 'kept.txt'
        Set-Content -LiteralPath $kept -Value 'kept' -NoNewline

        Reset-WindowsAccessControlLabRunnerDirectory -Path $script:directory -Resolution $script:resolution -WhatIf

        $kept | Should -Exist
    }
}
