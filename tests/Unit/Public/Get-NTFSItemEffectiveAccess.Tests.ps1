BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSItemEffectiveAccess remote boundary' -Tag 'Unit', 'WindowsOnly' {
    It 'Should reject a UNC target before descriptor or Authz evaluation' {
        InModuleScope WindowsAccessControl {
            Mock Resolve-NTFSPath {
                [pscustomobject]@{ FullName = '\\server.example.test\share\file.txt' }
            }
            Mock Get-Acl { throw 'Descriptor evaluation must not run.' }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                {
                    Get-NTFSItemEffectiveAccess -LiteralPath '\\server.example.test\share\file.txt'
                } | Should -Throw -ExpectedMessage (
                    '*Remote and combined effective-access evaluation is unsupported*'
                )
            } finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            Should -Invoke Get-Acl -Times 0 -Exactly
        }
    }
}