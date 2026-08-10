function ConvertTo-WindowsAccessRightsDisplay {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 0xFFFFFFFFL)]
        [long]$AccessMask,

        [Parameter(Mandatory)]
        [type]$RightsType
    )

    $mask = [uint64]$AccessMask
    $values = [uint64[]]@(
        foreach ($value in [System.Enum]::GetValues($RightsType)) {
            [uint64]([int64]$value -band 0xFFFFFFFFL)
        }
    )
    [System.Array]::Sort($values)

    # Repeat the greedy decomposition Enum.ToString performs so that the part
    # the enum can name is still rendered by .NET, and only the bits it has no
    # name for are left over. Enum.ToString abandons every name and returns the
    # signed mask as soon as one bit is unnameable.
    $residual = $mask
    for ($index = $values.Length - 1; $index -ge 0; $index--) {
        $value = $values[$index]
        if ($value -ne 0 -and ($residual -band $value) -eq $value) {
            $residual = $residual -bxor $value
        }
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $named = $mask -bxor $residual
    if ($named -ne 0 -or $residual -eq 0) {
        $parts.Add([string][System.Enum]::ToObject($RightsType, [int64]$named))
    }

    # Windows keeps the GENERIC_* bits of an inheritable ACE and maps them per
    # object type on access, and the standard rights above them are legal in any
    # mask, so an object family whose enum omits them still has to report them by
    # name. Ascending bit order matches Enum.ToString output.
    $standardRightName = [ordered]@{
        0x01000000L = 'AccessSystemSecurity'
        0x02000000L = 'MaximumAllowed'
        0x10000000L = 'GenericAll'
        0x20000000L = 'GenericExecute'
        0x40000000L = 'GenericWrite'
        0x80000000L = 'GenericRead'
    }
    foreach ($entry in $standardRightName.GetEnumerator()) {
        $bit = [uint64]$entry.Key
        if (($residual -band $bit) -eq $bit) {
            $parts.Add($entry.Value)
            $residual = $residual -bxor $bit
        }
    }

    if ($residual -ne 0) {
        $parts.Add(('0x{0:X8}' -f $residual))
    }

    $parts -join ', '
}
