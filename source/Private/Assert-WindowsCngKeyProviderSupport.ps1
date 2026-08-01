function Assert-WindowsCngKeyProviderSupport {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName
    )

    $supportedProvider = 'Microsoft Software Key Storage Provider'
    if ($ProviderName -cne $supportedProvider) {
        throw [NotSupportedException]::new(
            "Only persisted RSA keys in '$supportedProvider' are supported. Provider '$ProviderName' is not admitted."
        )
    }

    # The allow-list alone would trust a substituted provider registration, so
    # the implementation type is confirmed against the provider itself. A probe
    # failure throws and therefore fails closed.
    $implementation = Get-WindowsCngProviderImplementation -ProviderName $ProviderName
    if (-not $implementation.IsSoftwareOnly) {
        throw [NotSupportedException]::new(
            (
                "Key storage provider '$ProviderName' reports implementation type " +
                ('0x{0:X8}' -f $implementation.ImplementationType) +
                '. Hardware, removable, and hardware-random providers are not supported.'
            )
        )
    }
}
