function ConvertTo-WindowsCryptoKeyEffectiveMask {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)]
        [long]$AccessMask
    )

    # A live probe showed Microsoft Software Key Storage Provider stores a
    # candidate ACE with the matching generic bit added, so a requested mask and
    # the stored mask are never bit-identical. Expand every generic bit through
    # the file generic mapping before comparing.
    $genericMap = @{
        0x80000000L = 0x00120089L
        0x40000000L = 0x00120116L
        0x20000000L = 0x001200A0L
        0x10000000L = 0x001F01FFL
    }
    $effective = $AccessMask -band 0xFFFFFFFFL
    foreach ($genericBit in $genericMap.Keys) {
        if (($effective -band $genericBit) -ne 0) {
            $effective = $effective -bor $genericMap[$genericBit]
        }
    }
    $effective -band 0x0FFFFFFFL
}
