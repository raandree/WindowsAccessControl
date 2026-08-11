function Resolve-NTFSPath {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([System.IO.FileSystemInfo])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')]
        [string[]]$LiteralPath
    )

    $getItemParameters = @{
        ErrorAction = 'Stop'
    }

    if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
        $getItemParameters.LiteralPath = $LiteralPath
        $suppliedPaths = $LiteralPath
    } else {
        $getItemParameters.Path = $Path
        $suppliedPaths = $Path
    }

    foreach ($suppliedPath in $suppliedPaths) {
        if ([string]::IsNullOrEmpty($suppliedPath)) {
            continue
        }
        # The FileSystem provider does not normalize a device-namespace path, so
        # the resolved name is not a canonical target and a misbinding has been
        # reported to destroy a system. Refuse it instead of guessing.
        if ($suppliedPath.StartsWith('\\?\', [System.StringComparison]::Ordinal) -or
            $suppliedPath.StartsWith('\\.\', [System.StringComparison]::Ordinal)) {
            $exception = [System.ArgumentException]::new(
                "Path '$suppliedPath' uses the Win32 device namespace. Supply a file system path without the '\\?\' or '\\.\' prefix."
            )
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'WindowsAccessControl.DeviceNamespacePathNotSupported',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $suppliedPath
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        # A bare drive specification resolves to the current location of that
        # drive, not to the volume root, so it silently addresses a different
        # directory than the caller wrote.
        if ($suppliedPath -match '^[A-Za-z]:$') {
            $exception = [System.ArgumentException]::new(
                "Path '$suppliedPath' is a drive specification, which resolves to the current location of that drive. Supply '$suppliedPath\' for the volume root directory."
            )
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'WindowsAccessControl.AmbiguousDriveSpecification',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $suppliedPath
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }

    foreach ($item in @(Get-Item @getItemParameters)) {
        if ($item.PSProvider.Name -ne 'FileSystem') {
            $exception = [System.ArgumentException]::new(
                "Path '$($item.PSPath)' is not in the FileSystem provider."
            )
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'WindowsAccessControl.PathNotFileSystem',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $item
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $item
    }
}