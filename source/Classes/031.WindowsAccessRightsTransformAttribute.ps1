class WindowsAccessRightsTransformAttribute : System.Management.Automation.ArgumentTransformationAttribute {
    # The rights enum the transformed value must end up as.
    [type]$RightsType

    WindowsAccessRightsTransformAttribute([type]$rightsType) {
        if (-not $rightsType.IsEnum) {
            throw [System.ArgumentException]::new(
                "RightsType '$($rightsType.FullName)' is not an enumeration."
            )
        }
        $this.RightsType = $rightsType
    }

    [object] Transform(
        [System.Management.Automation.EngineIntrinsics]$engineIntrinsics,
        [object]$inputData
    ) {
        if ($null -eq $inputData) {
            return $inputData
        }

        $value = $inputData
        if ($value -is [System.Management.Automation.PSObject]) {
            $value = ([System.Management.Automation.PSObject]$value).BaseObject
        }
        # Binding re-runs the transformation over an unbound parameter while it
        # resolves a parameter set, so a null has to survive it untouched.
        if ($null -eq $value) {
            return $inputData
        }
        if ($value.GetType() -eq $this.RightsType) {
            return $value
        }

        $mask = $null
        if ($value -is [string]) {
            $text = ([string]$value).Trim()
            if ($text -match '^0[xX][0-9a-fA-F]{1,8}$') {
                $mask = [System.Convert]::ToInt64($text.Substring(2), 16)
            } elseif ($text -match '^-?\d+$') {
                $mask = [System.Int64]::Parse(
                    $text,
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
            }
        } elseif ($value -is [byte] -or $value -is [sbyte] -or
            $value -is [int16] -or $value -is [uint16] -or
            $value -is [int] -or $value -is [uint32] -or
            $value -is [int64] -or $value -is [uint64]) {
            $mask = [System.Convert]::ToInt64($value)
        }

        if ($null -eq $mask) {
            # A name, a comma-separated name list, or anything else stays with
            # the engine's own conversion so an unknown name is still rejected.
            return $inputData
        }
        if ($mask -lt [int]::MinValue -or $mask -gt [uint32]::MaxValue) {
            throw [System.ArgumentOutOfRangeException]::new(
                'inputData',
                $inputData,
                'An access mask must fit in 32 bits.'
            )
        }
        if ($mask -gt [int]::MaxValue) {
            $mask = $mask - 4294967296L
        }

        # Enum::ToObject keeps every bit, including the generic rights and
        # ACCESS_SYSTEM_SECURITY, that the engine's enum conversion rejects
        # because the enum has no name for them.
        return [System.Enum]::ToObject($this.RightsType, [int]$mask)
    }
}
