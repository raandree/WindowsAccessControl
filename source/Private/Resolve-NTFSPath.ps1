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
    } else {
        $getItemParameters.Path = $Path
    }

    foreach ($item in @(Get-Item @getItemParameters)) {
        if ($item.PSProvider.Name -ne 'FileSystem') {
            $exception = [System.ArgumentException]::new(
                "Path '$($item.PSPath)' is not in the FileSystem provider."
            )
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'NTFSPermission.PathNotFileSystem',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $item
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $item
    }
}