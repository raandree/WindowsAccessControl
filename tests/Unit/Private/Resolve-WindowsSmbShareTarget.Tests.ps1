BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Resolve-WindowsSmbShareTarget' -Tag 'Unit', 'WindowsOnly' {
    It 'Should reject wildcard share names before querying SMB state' {
        InModuleScope WindowsAccessControl {
            Mock Get-SmbShare {
                [pscustomobject]@{
                    Name = 'WacLab$'
                    ShareType = 'FileSystemDirectory'
                    SmbInstance = 'Default'
                    AvailabilityType = 'NonClustered'
                    Special = $false
                    ContinuouslyAvailable = $false
                    Infrastructure = $false
                    ShadowCopy = $false
                    Scoped = $false
                    Temporary = $false
                    ScopeName = '*'
                    Description = 'test'
                }
            }

            {
                Resolve-WindowsSmbShareTarget -Name 'Wac*'
            } | Should -Throw
            Should -Invoke Get-SmbShare -Times 0 -Exactly
        }
    }

    It 'Should reject unsupported SMB provider topology states' {
        $baseShare = [ordered]@{
            Name = 'WacLab$'
            ShareType = 'FileSystemDirectory'
            SmbInstance = 'Default'
            AvailabilityType = 'NonClustered'
            Special = $false
            ContinuouslyAvailable = $false
            Infrastructure = $false
            ShadowCopy = $false
            Scoped = $false
            Temporary = $false
            ScopeName = '*'
            Description = 'test'
        }
        $unsupported = @(
            @{ ShareType = 'Pipe' }
            @{ SmbInstance = 'CSV' }
            @{ AvailabilityType = 'Clustered' }
            @{ Infrastructure = $true }
            @{ ShadowCopy = $true }
            @{ Scoped = $true; ScopeName = 'Scope01' }
            @{ Temporary = $true }
        )

        foreach ($override in $unsupported) {
            $shareData = [ordered]@{}
            foreach ($key in $baseShare.Keys) {
                $shareData[$key] = $baseShare[$key]
            }
            foreach ($key in $override.Keys) {
                $shareData[$key] = $override[$key]
            }
            $share = [pscustomobject]$shareData
            InModuleScope WindowsAccessControl -Parameters @{ TestShare = $share } {
                Mock Get-SmbShare { $TestShare }

                {
                    Resolve-WindowsSmbShareTarget -Name 'WacLab$'
                } | Should -Throw
            }
        }
    }
}
