function Get-WindowsCngProviderImplementation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName
    )

    Initialize-WindowsAccessControlNativeType
    $flags = [WindowsAccessControl.NativeMethods]::GetKeyStorageProviderImplementationType(
        $ProviderName
    )

    # NCRYPT_IMPL_* flags from ncrypt.h. Only the software flag is safe to
    # mutate; hardware, removable, and hardware-RNG providers hold key material
    # outside this machine's control.
    $hardware = ($flags -band 0x1) -ne 0
    $software = ($flags -band 0x2) -ne 0
    $removable = ($flags -band 0x8) -ne 0
    $hardwareRandom = ($flags -band 0x10) -ne 0

    [pscustomobject]@{
        ProviderName     = $ProviderName
        ImplementationType = $flags
        IsHardware       = $hardware
        IsSoftware       = $software
        IsRemovable      = $removable
        IsHardwareRandom = $hardwareRandom
        IsSoftwareOnly   = $software -and -not ($hardware -or $removable -or $hardwareRandom)
    }
}
