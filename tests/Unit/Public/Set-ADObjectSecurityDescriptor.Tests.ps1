. "$PSScriptRoot\EnterpriseCommandContract.ps1"
Register-EnterpriseCommandContract `
    -Name 'Set-ADObjectSecurityDescriptor' `
    -RequiredParameters @('Server', 'DistinguishedName', 'AllowedBaseDistinguishedName', 'Sddl', 'Credential', 'TimeoutSeconds', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Describe 'Active Directory concurrency contract' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
    }

    It 'Should offer no staleness gate on <Name>' -ForEach @(
        @{ Name = 'Set-ADObjectSecurityDescriptor' }
        @{ Name = 'Add-ADObjectAccessRule' }
        @{ Name = 'Set-ADObjectAccessRule' }
        @{ Name = 'Remove-ADObjectAccessRule' }
        @{ Name = 'Clear-ADObjectAccessRule' }
    ) {
        $command = Get-Command -Name $Name -Module 'WindowsAccessControl' -ErrorAction Stop

        $command.Parameters.ContainsKey('RequireUnchanged') |
            Should -BeFalse -Because 'specification 0016 states that the directory family offers no staleness gate and that a caller compares ConcurrencyToken itself'
    }
}
