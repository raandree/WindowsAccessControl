function Assert-WindowsDescriptorUnchanged {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedToken,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$CurrentToken,

        [Parameter(Mandatory)]
        [string]$Target
    )

    if ([string]::IsNullOrEmpty($ExpectedToken)) {
        throw [InvalidOperationException]::new(
            'RequireUnchanged needs a descriptor that recorded a ConcurrencyToken when it was read.'
        )
    }
    if ($CurrentToken -cne $ExpectedToken) {
        throw [InvalidOperationException]::new(
            "The selected security descriptor sections of '$Target' changed after they were read. Re-read the descriptor and reapply the edit."
        )
    }
}
