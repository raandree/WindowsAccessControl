<#
    .SYNOPSIS
        Ownership and path decisions of the domain-lab acceptance runner.

    .DESCRIPTION
        Invoke-WindowsAccessControlLabAcceptance.ps1 sends the text of this file
        into every remote step that creates or deletes a directory on the
        management domain controller, so each decision is made by the machine
        that holds the directory. The runner marks every directory it creates
        and replaces a directory only when it is absent or carries that marker.

        The file only defines functions, so dot-sourcing it changes nothing.
#>

function Get-WindowsAccessControlLabRunnerMarker {
    <#
        .SYNOPSIS
            Returns the file name and text of the runner's ownership marker.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    [pscustomobject]@{
        FileName = '.windows-access-control-lab-runner'
        Text     = 'Created by the WindowsAccessControl domain-lab acceptance runner.'
    }
}

function Get-WindowsAccessControlLabRunnerProtectedPath {
    <#
        .SYNOPSIS
            Returns the directories a payload root must not lie under on this
            machine.

        .DESCRIPTION
            Reads the Windows directory, Program Files, ProgramData, and the
            user profile root of the machine that runs the function. A
            category that resolves to no directory stops the check rather than
            weakening it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $profileList = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' `
        -Name 'ProfilesDirectory' `
        -ErrorAction SilentlyContinue
    $userProfile = [Environment]::GetFolderPath('UserProfile')

    $categories = [ordered]@{
        'Windows directory'       = @(
            [Environment]::GetFolderPath('Windows')
            $env:SystemRoot
            $env:windir
        )
        'Program Files directory' = @(
            [Environment]::GetFolderPath('ProgramFiles')
            [Environment]::GetFolderPath('ProgramFilesX86')
            $env:ProgramFiles
            ${env:ProgramFiles(x86)}
            $env:ProgramW6432
        )
        'ProgramData directory'   = @(
            [Environment]::GetFolderPath('CommonApplicationData')
            $env:ProgramData
        )
        'user profile root'       = @(
            if ($profileList) {
                $profileList.ProfilesDirectory
            }
            if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
                [IO.Path]::GetDirectoryName($userProfile)
            }
        )
    }

    $protectedPaths = foreach ($category in $categories.GetEnumerator()) {
        $paths = @($category.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($paths.Count -eq 0) {
            throw "Cannot determine the $($category.Key) of '$env:COMPUTERNAME', so no payload root can be checked there."
        }

        foreach ($path in $paths) {
            [IO.Path]::GetFullPath($path).TrimEnd('\')
        }
    }

    $protectedPaths | Sort-Object -Unique
}

function Assert-WindowsAccessControlLabRunnerPayloadPath {
    <#
        .SYNOPSIS
            Rejects a payload root this machine must not use and returns the
            normalized path.

        .DESCRIPTION
            A payload root must be an absolute path on a local fixed drive. It
            must not be a drive root, pass through a junction or symbolic link,
            or lie under a protected directory of the machine that runs the
            function. Normalization resolves relative segments, separators,
            and 8.3 short names before any comparison.

        .PARAMETER Path
            The payload root to check.

        .PARAMETER ProtectedPath
            The directories the payload root must not lie under. It defaults to
            the protected directories of the machine that runs the function;
            an empty list is refused rather than treated as nothing to protect.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$ProtectedPath
    )

    if (-not $PSBoundParameters.ContainsKey('ProtectedPath')) {
        $ProtectedPath = @(Get-WindowsAccessControlLabRunnerProtectedPath)
    }

    $subject = "The payload root '$Path' on '$env:COMPUTERNAME'"
    $example = "Pass a dedicated directory such as 'C:\WacRepo'."
    if ($Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "$subject is not an absolute local path. $example"
    }

    # Wildcard and bracket characters would turn the -Path parameters further
    # down into patterns, and a second colon would name a data stream.
    $reservedCharacters = [char[]]([char[]]'*?"<>|[]' + [IO.Path]::GetInvalidPathChars())
    if ($Path.IndexOfAny($reservedCharacters) -ge 0 -or $Path.IndexOf([char]':', 2) -ge 0) {
        throw "$subject contains a character that a payload root must not use. $example"
    }

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        $fullPath = $null
    }
    if ($null -eq $fullPath -or $fullPath -notmatch '^[A-Za-z]:\\') {
        throw "$subject is not an absolute local path. $example"
    }

    $fullPath = $fullPath.TrimEnd('\')
    if ($fullPath.Length -le 2) {
        throw "$subject is a drive root. $example"
    }

    if ([IO.DriveInfo]::new($fullPath.Substring(0, 1)).DriveType -ne [IO.DriveType]::Fixed) {
        throw "$subject is not on a local fixed drive. $example"
    }

    foreach ($protected in $ProtectedPath) {
        if ([string]::IsNullOrWhiteSpace($protected)) {
            throw "$subject cannot be checked, because the -ProtectedPath list contains a blank entry."
        }

        $protectedFullPath = [IO.Path]::GetFullPath($protected).TrimEnd('\')
        if ($fullPath.Equals($protectedFullPath, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($protectedFullPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw (
                "$subject lies under the protected directory '$protectedFullPath'. Pass a dedicated " +
                'directory outside the Windows directory, Program Files, ProgramData, and the user ' +
                "profiles, such as 'C:\WacRepo'."
            )
        }
    }

    # A junction or symbolic link would let the path reach a directory the
    # comparison above never saw.
    $ancestor = $fullPath
    while ($ancestor.Length -gt 3) {
        if (Test-Path -LiteralPath $ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "$subject passes through the junction or symbolic link '$ancestor'. $example"
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }

    $fullPath
}

function Get-WindowsAccessControlLabRunnerDirectoryState {
    <#
        .SYNOPSIS
            Reports whether a directory is absent, owned by the runner, or not
            owned by it.

        .DESCRIPTION
            A directory is owned only when it is a real directory, not a
            junction or symbolic link, holds the runner's marker file with the
            runner's marker text, and contains no junction or symbolic link at
            any depth. Windows PowerShell 5.1 deletes through a junction during
            a recursive removal, so a tree with one is never treated as owned;
            the walk lists each link without entering it.

        .PARAMETER Path
            The directory to inspect.

        .OUTPUTS
            An object with Path, State (Absent, Owned, or Unowned), and Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $marker = Get-WindowsAccessControlLabRunnerMarker
    $state = 'Unowned'
    if (-not (Test-Path -LiteralPath $Path)) {
        $state = 'Absent'
        $reason = 'it does not exist.'
    }
    else {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $markerPath = Join-Path -Path $Path -ChildPath $marker.FileName
        if ($item -isnot [IO.DirectoryInfo]) {
            $reason = 'it is not a directory.'
        }
        elseif ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $reason = 'it is a junction or symbolic link, not a directory the runner created.'
        }
        elseif (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            $reason = "it carries no '$($marker.FileName)' ownership marker, so the runner did not create it."
        }
        elseif ([IO.File]::ReadAllText($markerPath).TrimEnd() -cne $marker.Text) {
            $reason = "its '$($marker.FileName)' marker does not hold the runner's ownership text."
        }
        else {
            $link = $null
            $pendingDirectories = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
            $pendingDirectories.Push($item)
            while ($null -eq $link -and $pendingDirectories.Count -gt 0) {
                foreach ($entry in $pendingDirectories.Pop().GetFileSystemInfos()) {
                    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                        $link = $entry.FullName
                        break
                    }
                    if ($entry -is [IO.DirectoryInfo]) {
                        $pendingDirectories.Push($entry)
                    }
                }
            }

            if ($link) {
                $reason = (
                    "it contains the junction or symbolic link '$link', which a recursive " +
                    'deletion could follow out of the directory.'
                )
            }
            else {
                $state = 'Owned'
                $reason = "it carries the runner's ownership marker."
            }
        }
    }

    [pscustomobject]@{
        Path   = $Path
        State  = $state
        Reason = $reason
    }
}

function Reset-WindowsAccessControlLabRunnerDirectory {
    <#
        .SYNOPSIS
            Replaces a runner-owned or absent directory with an empty, marked one.

        .DESCRIPTION
            Refuses a directory the runner does not own before deleting
            anything, and names the directory and the resolution. An owned
            directory is deleted and created again; an absent one is created.
            The marker is written as soon as the directory exists, so a later
            run can prove that the runner created it.

        .PARAMETER Path
            The directory to replace.

        .PARAMETER Resolution
            What the operator can do when the directory is refused.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Resolution
    )

    $ownership = Get-WindowsAccessControlLabRunnerDirectoryState -Path $Path
    if ($ownership.State -eq 'Unowned') {
        throw "Refusing to replace '$Path' on '$env:COMPUTERNAME': $($ownership.Reason) $Resolution"
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Replace the runner-owned directory')) {
        return
    }

    $marker = Get-WindowsAccessControlLabRunnerMarker
    if ($ownership.State -eq 'Owned') {
        # The marker goes last, so a deletion that fails part way still leaves
        # a directory the next run can prove it owns.
        Get-ChildItem -LiteralPath $Path -Force |
            Where-Object { $_.Name -ne $marker.FileName } |
            Remove-Item -Recurse -Force -ErrorAction Stop
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }

    $null = New-Item -Path $Path -ItemType Directory -ErrorAction Stop
    try {
        [IO.File]::WriteAllText(
            (Join-Path -Path $Path -ChildPath $marker.FileName),
            $marker.Text,
            [Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        $markerError = $_
        try {
            # This call created the directory a moment ago, so the runner owns it.
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
        catch {
            throw [AggregateException]::new(
                "Marking '$Path' and removing it again both failed.",
                [Exception[]]@($markerError.Exception, $_.Exception)
            )
        }
        throw $markerError
    }
}
