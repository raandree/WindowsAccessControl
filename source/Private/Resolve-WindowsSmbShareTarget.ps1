function Resolve-WindowsSmbShareTarget {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    process {
        $shareName = $Name.Trim()
        if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters(
                $shareName
            ) -or $shareName -match '[\\/:]' -or
            $shareName -in @('.', 'localhost')) {
            throw [System.NotSupportedException]::new(
                "Remote or qualified SMB share targets are not supported: '$Name'."
            )
        }
        if ($shareName -in @('ADMIN$', 'IPC$', 'print$') -or
            $shareName -match '^[A-Za-z]\$$') {
            throw [System.NotSupportedException]::new(
                "Administrative or special SMB shares are not supported: '$shareName'."
            )
        }

        $shares = @(Get-SmbShare -Name $shareName -ErrorAction Stop)
        if ($shares.Count -ne 1) {
            throw [System.InvalidOperationException]::new(
                "SMB share '$shareName' did not resolve to one local share."
            )
        }
        $share = $shares[0]
        if ($share.ShareType.ToString() -cne 'FileSystemDirectory' -or
            $share.SmbInstance.ToString() -cne 'Default' -or
            $share.AvailabilityType.ToString() -cne 'NonClustered' -or
            $share.Special -or
            $share.ContinuouslyAvailable -or
            $share.Infrastructure -or
            $share.ShadowCopy -or
            $share.Scoped -or
            $share.Temporary -or
            [string]$share.ScopeName -cne '*') {
            throw [System.NotSupportedException]::new(
                "Only ordinary nonclustered local filesystem SMB shares are supported: '$shareName'."
            )
        }

        [pscustomobject]@{
            ObjectType       = 'SmbShare'
            Path             = $share.Name
            ShareName        = $share.Name
            Description      = [string]$share.Description
            NativePath       = $share.Name
            NativeObjectType = [int][WindowsSecurityObjectType]::SmbShare
            DescriptorSource = 'Named'
            CanonicalTarget  = 'SmbShare:Local:{0}' -f $share.Name.ToUpperInvariant()
        }
    }
}
