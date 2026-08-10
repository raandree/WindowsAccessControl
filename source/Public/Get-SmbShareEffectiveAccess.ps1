function Get-SmbShareEffectiveAccess {
    <#
    .SYNOPSIS
        Gets bounded share-only effective access for local SMB shares.
    .DESCRIPTION
        Evaluates a local SMB share DACL through Windows Authz using a
        SID-derived context. The result excludes the backing NTFS DACL and can
        omit logon-specific groups. It is not a remote or combined access claim.
    .PARAMETER Name
        One or more unqualified ordinary local SMB share names.
    .PARAMETER Account
        The account name or SID evaluated by Authz. The current process
        identity is used when this parameter is omitted.
    .PARAMETER AccessRights
        Optional share rights to test against the granted mask. IsAllowed is
        null when no requested rights are supplied.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical share targets from 1 to 64.
    .EXAMPLE
        Get-SmbShareEffectiveAccess -Name 'Data$' `
            -Account 'CONTOSO\Analysts' `
            -AccessRights Read

        Evaluates the local Data share DACL only for the Analysts SID context.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.SmbShareEffectiveAccess
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ShareName')]
        [object[]]$Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter()]
        [WindowsSmbShareRights]$AccessRights,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    begin {
        Initialize-WindowsAccessControlNativeType
        if ($PSBoundParameters.ContainsKey('Account')) {
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
        }
        else {
            $securityIdentifier = [Security.Principal.WindowsIdentity]::GetCurrent().User
        }
        try {
            $accountName = $securityIdentifier.Translate(
                [Security.Principal.NTAccount]
            ).Value
        }
        catch [Security.Principal.IdentityNotMappedException] {
            $accountName = $securityIdentifier.Value
        }
        $sidBytes = [byte[]]::new($securityIdentifier.BinaryLength)
        $securityIdentifier.GetBinaryForm($sidBytes, 0)
        $testRequestedRights = $PSBoundParameters.ContainsKey('AccessRights')
    }

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsSmbShareCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            $descriptorBytes = Get-WindowsNamedSecurityDescriptor `
                -NativePath $target.NativePath `
                -NativeObjectType $target.NativeObjectType `
                -Sections (
                    [WindowsSecurityDescriptorSection]::Owner -bor
                    [WindowsSecurityDescriptorSection]::Group -bor
                    [WindowsSecurityDescriptorSection]::Access
                )
            $accessMask = [WindowsAccessControl.NativeMethods]::GetEffectiveAccess(
                $descriptorBytes,
                $sidBytes
            )
            $isAllowed = $null
            if ($testRequestedRights) {
                $requestedMask = [BitConverter]::ToUInt32(
                    [BitConverter]::GetBytes([int]$AccessRights),
                    0
                )
                $isAllowed = ($accessMask -band $requestedMask) -eq $requestedMask
            }

            $result = [pscustomobject]@{
                ObjectType          = 'SmbShare'
                Path                = $target.ShareName
                ShareName           = $target.ShareName
                CanonicalTarget     = $target.CanonicalTarget
                Account             = $accountName
                SID                 = $securityIdentifier.Value
                AccessMask          = $accessMask
                EffectiveRights     = ConvertTo-WindowsSmbShareRights `
                    -AccessMask $accessMask
                EffectiveRightsDisplay = ConvertTo-WindowsAccessRightsDisplay `
                    -AccessMask $accessMask `
                    -RightsType ([WindowsSmbShareRights])
                RequestedRights     = if ($testRequestedRights) {
                    $AccessRights
                }
                else {
                    $null
                }
                IsAllowed             = $isAllowed
                AuthorizationContext = 'LocalSidDerived'
                IncludesBackingNtfs  = $false
            }
            $result.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.SmbShareEffectiveAccess'
            )
            $result
        }
    }
}