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

    $metadataError = $null
    try {
        $currentShare = Get-SmbShare -Name $Target.ShareName -ErrorAction Stop
        if ([string]$currentShare.Description -cne [string]$Target.Description) {
            Set-SmbShare `
                -Name $Target.ShareName `
                -Description ([string]$Target.Description) `
                -Confirm:$false `
                -ErrorAction Stop
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
        throw $metadataError
    }
}
