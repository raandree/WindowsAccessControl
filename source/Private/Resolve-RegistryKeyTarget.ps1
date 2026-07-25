function Resolve-RegistryKeyTarget {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [object]$Path,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default
    )

    process {
        $pathValue = if ($Path -is [Microsoft.Win32.RegistryKey]) {
            $bindingFlags = [Reflection.BindingFlags]'Instance,NonPublic'
            $remoteField = $null
            foreach ($fieldName in '_remoteKey', 'remoteKey', 'm_remoteKey') {
                $remoteField = $Path.GetType().GetField($fieldName, $bindingFlags)
                if ($remoteField) {
                    break
                }
            }
            if (-not $remoteField) {
                throw [System.NotSupportedException]::new(
                    'Cannot verify that the RegistryKey target is local; remote objects are not supported.'
                )
            }
            if ([bool]$remoteField.GetValue($Path)) {
                throw [System.NotSupportedException]::new(
                    "Remote RegistryKey objects are not supported: '$($Path.Name)'."
                )
            }
            $Path.Name
        } elseif ($Path.PSObject.Properties['PSPath']) {
            [string]$Path.PSPath
        } else {
            [string]$Path
        }
        if ([string]::IsNullOrWhiteSpace($pathValue)) {
            throw [System.ArgumentException]::new('A registry key path is required.')
        }
        if ($pathValue -match '^(?:Microsoft\.PowerShell\.Core\\Registry::)?\\\\') {
            throw [System.NotSupportedException]::new(
                "Native remote registry targets are not supported: '$pathValue'."
            )
        }

        $normalized = $pathValue -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $normalized = $normalized.Trim()
        if ($normalized -match '^(?:HKLM|HKCU|HKCR|HKU|HKCC):/') {
            $normalized = $normalized.Replace('/', '\')
        }
        $hivePattern = '^(?<Hive>HKEY_LOCAL_MACHINE|HKLM|MACHINE|HKEY_CURRENT_USER|HKCU|CURRENT_USER|HKEY_CLASSES_ROOT|HKCR|CLASSES_ROOT|HKEY_USERS|HKU|USERS|HKEY_CURRENT_CONFIG|HKCC)(?::)?(?:\\(?<SubPath>.*))?$'
        if ($normalized -notmatch $hivePattern) {
            throw [System.ArgumentException]::new(
                "Registry key path '$pathValue' does not use a supported local hive."
            )
        }

        $subPath = [string]$Matches.SubPath
        $nativeHive = switch -Regex ($Matches.Hive.ToUpperInvariant()) {
            '^(HKEY_LOCAL_MACHINE|HKLM|MACHINE)$' { 'MACHINE'; break }
            '^(HKEY_CURRENT_USER|HKCU|CURRENT_USER)$' { 'CURRENT_USER'; break }
            '^(HKEY_CLASSES_ROOT|HKCR|CLASSES_ROOT)$' { 'CLASSES_ROOT'; break }
            '^(HKEY_USERS|HKU|USERS)$' { 'USERS'; break }
            '^(HKEY_CURRENT_CONFIG|HKCC)$' {
                $subPath = @(
                    'SYSTEM\CurrentControlSet\Hardware Profiles\Current'
                    $subPath
                ) | Where-Object { $_ }
                $subPath = $subPath -join '\'
                'MACHINE'
                break
            }
        }
        $providerHive = switch ($nativeHive) {
            'MACHINE' { 'HKLM:' }
            'CURRENT_USER' { 'HKCU:' }
            'CLASSES_ROOT' { 'HKCR:' }
            'USERS' { 'HKU:' }
        }
        $nativePath = (@($nativeHive, $subPath) | Where-Object { $_ }) -join '\'
        $providerPath = (@($providerHive, $subPath) | Where-Object { $_ }) -join '\'
        $nativeObjectType = switch ($RegistryView) {
            Registry32 { [int][WindowsSecurityObjectType]::Registry32 }
            Registry64 { [int][WindowsSecurityObjectType]::Registry64 }
            default { [int][WindowsSecurityObjectType]::RegistryKey }
        }

        [pscustomobject]@{
            ObjectType       = 'RegistryKey'
            Path             = $providerPath
            NativePath       = $nativePath
            NativeObjectType = $nativeObjectType
            RegistryView     = $RegistryView.ToString()
            CanonicalTarget  = 'RegistryKey:{0}:{1}' -f $RegistryView, $nativePath.ToUpperInvariant()
        }
    }
}
