function Assert-WindowsCngKeyCriticalBinding {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.CngKey]$Key
    )

    # The gate is keyed on the key rather than on a certificate, so it applies
    # identically whether the caller addressed the key through a certificate or
    # through its provider and key name.
    $bindings = @(Get-WindowsCertificateCriticalBinding -Key $Key)
    if ($bindings.Count -eq 0) {
        return
    }
    $summary = (
        $bindings | ForEach-Object { "$($_.Binding) (certificate $($_.Thumbprint)): $($_.Detail)" }
    ) -join ' '
    throw [InvalidOperationException]::new(
        (
            "Refusing to change the DACL of private key '$($Key.KeyName)' in " +
            "'$($Key.Provider.Provider)' because that key serves a critical binding. $summary"
        )
    )
}
