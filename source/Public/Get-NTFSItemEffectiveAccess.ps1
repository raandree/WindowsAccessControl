function Get-NTFSItemEffectiveAccess {
    <#
    .SYNOPSIS
        Gets effective NTFS access for a user SID.

    .DESCRIPTION
        Uses the Windows Authz API with MAXIMUM_ALLOWED to evaluate a file or
        directory security descriptor for a valid user SID. SID-based contexts
        can omit logon-specific groups and are less complete than a live token.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        The user account name or SID evaluated by Authz. The current process
        identity is used when this parameter is omitted.

    .PARAMETER AccessRights
        Optional rights to test against the granted mask. IsAllowed is null
        when no requested rights are supplied.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Get-NTFSItemEffectiveAccess -LiteralPath C:\Data -Account 'CONTOSO\Alice' -AccessRights Modify

        Evaluates whether Alice receives Modify rights on C:\Data.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        WindowsAccessControl.EffectiveAccess
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path = '.',

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter()]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    begin {
        Initialize-WindowsAccessControlNativeType
        if ($PSBoundParameters.ContainsKey('Account')) {
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
        } else {
            $securityIdentifier = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        }
        $accountName = $null
        try {
            $accountName = $securityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
        } catch [System.Security.Principal.IdentityNotMappedException] {
            $accountName = $securityIdentifier.Value
        }
        $sidBytes = [byte[]]::new($securityIdentifier.BinaryLength)
        $securityIdentifier.GetBinaryForm($sidBytes, 0)
        $testRequestedRights = $PSBoundParameters.ContainsKey('AccessRights')
    }

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -ConfirmationImpact None
            return
        }
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $resolvedPath = [string]$item.FullName
            $isExtendedUnc = $resolvedPath.StartsWith(
                '\\?\UNC\',
                [System.StringComparison]::OrdinalIgnoreCase
            )
            $isStandardUnc = $resolvedPath.StartsWith(
                '\\',
                [System.StringComparison]::Ordinal
            ) -and -not $resolvedPath.StartsWith(
                '\\?\',
                [System.StringComparison]::Ordinal
            )
            if ($isStandardUnc -or $isExtendedUnc) {
                throw [System.NotSupportedException]::new(
                    'Remote and combined effective-access evaluation is unsupported. Run the local NTFS evaluation on a local target only.'
                )
            }

            $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $descriptorBytes = $security.GetSecurityDescriptorBinaryForm()
            $accessMask = [WindowsAccessControl.NativeMethods]::GetEffectiveAccess($descriptorBytes, $sidBytes)
            # An enum cast rejects a granted mask that carries a bit FileSystemRights
            # has no name for, so the value is boxed rather than converted.
            $effectiveMask = [uint64]$accessMask
            $effectiveRights = [System.Enum]::ToObject(
                [System.Security.AccessControl.FileSystemRights],
                [int64]$effectiveMask
            )
            $isAllowed = $null
            if ($testRequestedRights) {
                $requestedMask = [uint32][int]$AccessRights
                $isAllowed = ($accessMask -band $requestedMask) -eq $requestedMask
            }

            $result = [pscustomobject]@{
                Path                   = $item.FullName
                Account                = $accountName
                SID                    = $securityIdentifier.Value
                AccessMask             = $accessMask
                EffectiveRights        = $effectiveRights
                EffectiveRightsDisplay = ConvertTo-WindowsAccessRightsDisplay `
                    -AccessMask $effectiveMask `
                    -RightsType ([System.Security.AccessControl.FileSystemRights])
                RequestedRights        = if ($testRequestedRights) { $AccessRights } else { $null }
                IsAllowed              = $isAllowed
            }
            $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.EffectiveAccess')
            $result
        }
    }
}
