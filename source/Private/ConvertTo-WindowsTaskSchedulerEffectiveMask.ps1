function ConvertTo-WindowsTaskSchedulerEffectiveMask {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [int]$AccessMask
    )

    $effectiveMask = $AccessMask
    if (($AccessMask -band 0x10000000) -ne 0) {
        $effectiveMask = $effectiveMask -bor 0x001F01FF
    }
    if (($AccessMask -band 0x20000000) -ne 0) {
        $effectiveMask = $effectiveMask -bor 0x001200A0
    }
    if (($AccessMask -band 0x40000000) -ne 0) {
        $effectiveMask = $effectiveMask -bor 0x00120116
    }
    if (($AccessMask -band [int]::MinValue) -ne 0) {
        $effectiveMask = $effectiveMask -bor 0x00120089
    }
    $effectiveMask
}
