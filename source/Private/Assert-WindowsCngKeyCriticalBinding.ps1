function Assert-WindowsCngKeyCriticalBinding {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $bindings = @(Get-WindowsCertificateCriticalBinding -Certificate $Certificate)
    if ($bindings.Count -eq 0) {
        return
    }
    $summary = (
        $bindings | ForEach-Object { "$($_.Binding) (certificate $($_.Thumbprint)): $($_.Detail)" }
    ) -join ' '
    throw [InvalidOperationException]::new(
        (
            'Refusing to change the private key of certificate ' +
            "'$($Certificate.Thumbprint)' because the same key serves a critical binding. $summary"
        )
    )
}
