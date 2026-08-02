function New-WindowsCertificatePrivateKeyTargetParameter {
    <#
        .SYNOPSIS
            Builds the selector arguments for one private-key target.

        .DESCRIPTION
            Every private-key command accepts the same two selectors: an exact
            caller-owned certificate, or the provider, key name, and key scope of
            a persisted key. Building the argument set in one place keeps the two
            forms from drifting apart and keeps each command free of a conditional
            argument list.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This helper only builds an in-memory argument set.'
    )]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Certificate', 'Key')]
        [string]$ParameterSetName,

        [Parameter()]
        [AllowNull()]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$KeyScope
    )

    $parameters = @{
        ProviderName = $ProviderName
        KeyName      = $KeyName
    }
    if ($ParameterSetName -eq 'Key') {
        if ($KeyScope -notin @('Machine', 'User')) {
            throw [ArgumentException]::new(
                'A key-addressed private-key target requires the Machine or User key scope.'
            )
        }
        $parameters['KeyScope'] = $KeyScope
        return $parameters
    }
    if ($null -eq $Certificate) {
        throw [ArgumentException]::new(
            'A certificate-addressed private-key target requires a certificate.'
        )
    }
    $parameters['Certificate'] = $Certificate
    $parameters
}
