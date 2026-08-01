function Get-WindowsServiceStoreCertificate {
    [CmdletBinding()]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$StoreName
    )

    # A service certificate store such as the NTDS store a domain controller
    # uses for LDAPS is not reachable through StoreLocation, so it is opened
    # natively. A store that does not exist yields nothing, which is the normal
    # state on most machines; a store that exists and cannot be opened throws so
    # a caller gate fails closed.
    Initialize-WindowsAccessControlNativeType
    $encodedCertificates = [WindowsAccessControl.NativeMethods]::GetServiceStoreCertificates(
        $ServiceName,
        $StoreName
    )
    if ($null -eq $encodedCertificates) {
        return
    }
    foreach ($encoded in $encodedCertificates) {
        [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$encoded)
    }
}
