function Get-WindowsSecurityDescriptorConcurrencyToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Sddl
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Sddl))
    } finally {
        $sha256.Dispose()
    }
    [System.BitConverter]::ToString($hash).Replace('-', '')
}
