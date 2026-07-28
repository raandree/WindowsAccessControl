function Get-WindowsCngKeySecurityDescriptor {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.CngKey]$Key
    )

    # NCryptGetProperty forwards DACL_SECURITY_INFORMATION (0x04) and
    # NCRYPT_SILENT_FLAG (0x40) through CngPropertyOptions.
    $daclAndSilent = [Security.Cryptography.CngPropertyOptions]68
    $property = $Key.GetProperty('Security Descr', $daclAndSilent)
    $descriptorBytes = [byte[]]$property.GetValue()
    if ($null -eq $descriptorBytes -or $descriptorBytes.Length -eq 0) {
        throw [InvalidOperationException]::new(
            'The CNG provider returned an empty private-key security descriptor.'
        )
    }
    $null = [Security.AccessControl.RawSecurityDescriptor]::new(
        $descriptorBytes,
        0
    )
    Write-Output -InputObject $descriptorBytes -NoEnumerate
}