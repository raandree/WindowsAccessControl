function Set-WindowsSmbShareSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this persistence boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [byte[]]$CurrentSecurityDescriptor
    )

    # SE_LMSHARE writes can clear the share description. Read it as close to the
    # native write as possible so the compensation never replays a stale value.
    $descriptionBefore = [string](
        Get-SmbShare -Name $Target.ShareName -ErrorAction Stop
    ).Description

    $writeError = $null
    try {
        Set-WindowsNamedSecurityDescriptor `
            -NativePath $Target.NativePath `
            -NativeObjectType $Target.NativeObjectType `
            -Sections Access `
            -SecurityDescriptor $SecurityDescriptor `
            -CurrentSecurityDescriptor $CurrentSecurityDescriptor
    }
    catch {
        $writeError = $_
    }

    # A step after a committed DACL write must not report failure for a change
    # that is already live, so its warnings ignore a Stop or Inquire preference.
    $postWriteWarningAction = if ($WarningPreference -in 'Stop', 'Inquire') {
        'Continue'
    }
    else {
        $WarningPreference
    }
    $metadataError = $null
    try {
        $descriptionAfter = [string](
            Get-SmbShare -Name $Target.ShareName -ErrorAction Stop
        ).Description
        if ($descriptionAfter -cne $descriptionBefore) {
            if ($descriptionAfter.Length -eq 0) {
                Set-SmbShare `
                    -Name $Target.ShareName `
                    -Description $descriptionBefore `
                    -Confirm:$false `
                    -ErrorAction Stop
                Write-Verbose -Message (
                    "Restored the description of SMB share '{0}' to '{1}' after the DACL write cleared it." -f
                        $Target.ShareName, $descriptionBefore
                )
            }
            else {
                Write-Warning -Message (
                    "The description of SMB share '{0}' changed while its DACL was written and was left as it is. The description before the write was '{1}'." -f
                        $Target.ShareName, $descriptionBefore
                ) -WarningAction $postWriteWarningAction
            }
        }
    }
    catch {
        $metadataError = $_
    }

    if ($writeError -and $metadataError) {
        throw [AggregateException]::new(
            'The SMB share DACL write and description restoration both failed.',
            [Exception[]]@($writeError.Exception, $metadataError.Exception)
        )
    }
    if ($writeError) {
        throw $writeError
    }
    if ($metadataError) {
        Write-Warning -Message (
            "The DACL of SMB share '{0}' was written, but its description could not be checked or restored: {1} The description before the write was '{2}'." -f
                $Target.ShareName, $metadataError.Exception.Message, $descriptionBefore
        ) -WarningAction $postWriteWarningAction
    }
}
