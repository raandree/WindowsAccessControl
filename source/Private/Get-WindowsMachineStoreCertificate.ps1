function Get-WindowsMachineStoreCertificate {
    [CmdletBinding()]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$StoreName,

        [Parameter()]
        [switch]$Required
    )

    # The certificate PSDrive is not present in every runspace, so the store is
    # opened through the .NET API instead. OpenExistingOnly keeps this read-only
    # path from creating the store's registry key for a name that does not
    # exist. A store that must exist and cannot be opened throws so a caller
    # gate fails closed.
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName,
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    try {
        try {
            $store.Open(
                [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
                [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
            )
        }
        catch {
            if ($Required) {
                throw [InvalidOperationException]::new(
                    "Unable to open the local machine certificate store '$StoreName': $($_.Exception.Message)"
                )
            }
            return
        }
        foreach ($certificate in $store.Certificates) {
            $certificate
        }
    }
    finally {
        $store.Close()
    }
}
