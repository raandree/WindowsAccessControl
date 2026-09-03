BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
}

Describe 'Get-WindowsSecurityDescriptorRecordHash' -Tag 'Unit', 'WindowsOnly' {
    It 'Should produce the fixed process record hash in every culture and edition' {
        $record = [pscustomobject]@{
            RecordVersion         = 1
            ObjectFamily         = 'Process'
            Target               = 'PID:4242'
            Path                 = $null
            CanonicalTarget      = 'Process:4242:133700000000000000'
            ItemType             = $null
            RegistryView         = $null
            ProcessId            = [long]4242
            CreationTimeFileTime = [long]133700000000000000
            Sddl                 = 'D:(A;;GR;;;WD)'
            Sections             = 4
        }
        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture =
                [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
            $hash = & $script:module {
                param($InputRecord)
                Get-WindowsSecurityDescriptorRecordHash -Record $InputRecord
            } $record
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }
        $digest = -join @($hash | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })

        $digest | Should -BeExactly (
            'D65346B006C6B524A1152FE63143ABB76547D55CD25B676FF8165E7D60BD0F0F'
        )
    }
}
