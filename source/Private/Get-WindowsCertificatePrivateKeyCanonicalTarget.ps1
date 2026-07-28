function Get-WindowsCertificatePrivateKeyCanonicalTarget {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UniqueName,

        [Parameter(Mandatory)]
        [ValidateSet('Machine', 'User')]
        [string]$KeyScope
    )

    $stream = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new(
        $stream,
        [Text.UTF8Encoding]::new($false),
        $true
    )
    try {
        foreach ($component in @(
                'WindowsAccessControl.CertificatePrivateKey.Cng.v1'
                $KeyScope
                $ProviderName.ToUpperInvariant()
                $UniqueName
            )) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($component)
            $writer.Write([int]$bytes.Length)
            $writer.Write($bytes)
        }
        $writer.Flush()
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream.ToArray())
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
    $hash = -join ($hashBytes | ForEach-Object { $_.ToString('X2') })
    'CertificatePrivateKey:Cng:{0}:{1}' -f $KeyScope, $hash
}