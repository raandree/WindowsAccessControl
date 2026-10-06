BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new('D:(A;;FA;;;BA)')
    $script:descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($script:descriptorBytes, 0)
}

Describe 'Set-WindowsSmbShareSecurityDescriptor description handling' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        InModuleScope WindowsAccessControl {
            $script:testTarget = [pscustomobject]@{
                ShareName = 'WacLab$'
                Description = 'Captured at resolution'
                NativePath = 'WacLab$'
                NativeObjectType = [int][WindowsSecurityObjectType]::SmbShare
            }
            Mock Get-SmbShare {
                [pscustomobject]@{
                    Name = 'WacLab$'
                    Description = $script:liveDescription
                }
            }
            Mock Set-SmbShare {
                $script:liveDescription = $Description
            }
        }
    }

    It 'Should keep a description edited after the target was resolved' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Edited after resolution'
            Mock Set-WindowsNamedSecurityDescriptor { }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            $script:liveDescription | Should -BeExactly 'Edited after resolution'
            Should -Invoke Set-SmbShare -Times 0 -Exactly
            $smbWarnings | Should -BeNullOrEmpty
        }
    }

    It 'Should keep and report a description edited during the DACL write' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = 'Edited during the write'
            }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            $script:liveDescription | Should -BeExactly 'Edited during the write'
            Should -Invoke Set-SmbShare -Times 0 -Exactly
            $smbWarnings | Should -HaveCount 1
            [string]$smbWarnings[0] |
                Should -BeLike '*''WacLab$''*changed while its DACL was written*''Captured at resolution''*'
        }
    }

    It 'Should restore the description the DACL write cleared' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Edited after resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = ''
            }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            $script:liveDescription | Should -BeExactly 'Edited after resolution'
            Should -Invoke Set-SmbShare -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'WacLab$' -and $Description -ceq 'Edited after resolution'
            }
            $smbWarnings | Should -BeNullOrEmpty
        }
    }

    It 'Should report a restored description in the verbose stream' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = ''
            }

            $verboseRecords = @(
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $script:testTarget `
                    -SecurityDescriptor $Bytes `
                    -Verbose 4>&1 |
                    Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and [string]$_ -like '*restored*' }
            )

            $verboseRecords | Should -HaveCount 1
            [string]$verboseRecords[0] |
                Should -BeLike '*restored*''WacLab$''*''Captured at resolution''*'
        }
    }

    It 'Should warn instead of failing when restoring the description fails after a committed write' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = ''
            }
            Mock Set-SmbShare { throw 'Description restoration failed.' }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            $smbWarnings | Should -HaveCount 1
            [string]$smbWarnings[0] |
                Should -BeLike '*DACL of SMB share ''WacLab$'' was written*Description restoration failed*''Captured at resolution''*'
        }
    }

    It 'Should warn instead of failing when the description cannot be read after a committed write' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            $script:getSmbShareCalls = 0
            Mock Get-SmbShare {
                $script:getSmbShareCalls++
                if ($script:getSmbShareCalls -gt 1) {
                    throw 'SMB provider unavailable after the write.'
                }
                [pscustomobject]@{
                    Name = 'WacLab$'
                    Description = $script:liveDescription
                }
            }
            Mock Set-WindowsNamedSecurityDescriptor { }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 1 -Exactly
            $smbWarnings | Should -HaveCount 1
            [string]$smbWarnings[0] |
                Should -BeLike '*DACL of SMB share ''WacLab$'' was written*SMB provider unavailable after the write*'
        }
    }

    It 'Should not let a stop warning preference fail a committed write' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = 'Edited during the write'
            }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction Stop 3>$null

            $script:liveDescription | Should -BeExactly 'Edited during the write'
            $smbWarnings | Should -HaveCount 1
        }
    }

    It 'Should not write an unchanged description' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor { }

            Set-WindowsSmbShareSecurityDescriptor `
                -Target $script:testTarget `
                -SecurityDescriptor $Bytes `
                -WarningVariable smbWarnings `
                -WarningAction SilentlyContinue

            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 1 -Exactly
            Should -Invoke Set-SmbShare -Times 0 -Exactly
            $smbWarnings | Should -BeNullOrEmpty
        }
    }

    It 'Should not write the DACL when the description cannot be read first' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            Mock Get-SmbShare { throw 'SMB provider unavailable.' }
            Mock Set-WindowsNamedSecurityDescriptor { }

            {
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $script:testTarget `
                    -SecurityDescriptor $Bytes
            } | Should -Throw -ExpectedMessage '*SMB provider unavailable*'
            Should -Invoke Set-WindowsNamedSecurityDescriptor -Times 0 -Exactly
            Should -Invoke Set-SmbShare -Times 0 -Exactly
        }
    }

    It 'Should restore a cleared description and still report the failed write' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = ''
                throw 'Native DACL write failed.'
            }

            {
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $script:testTarget `
                    -SecurityDescriptor $Bytes
            } | Should -Throw -ExpectedMessage '*Native DACL write failed*'
            $script:liveDescription | Should -BeExactly 'Captured at resolution'
        }
    }

    It 'Should aggregate a failed write and a failed description restoration' {
        InModuleScope WindowsAccessControl -Parameters @{ Bytes = $script:descriptorBytes } {
            $script:liveDescription = 'Captured at resolution'
            Mock Set-WindowsNamedSecurityDescriptor {
                $script:liveDescription = ''
                throw 'Native DACL write failed.'
            }
            Mock Set-SmbShare { throw 'Description restoration failed.' }

            $failure = $null
            try {
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $script:testTarget `
                    -SecurityDescriptor $Bytes
            }
            catch {
                $failure = $_
            }

            $failure | Should -Not -BeNullOrEmpty
            $failure.Exception | Should -BeOfType ([AggregateException])
            $failure.Exception.InnerExceptions | Should -HaveCount 2
            $failure.Exception.InnerExceptions[0].Message | Should -BeLike '*Native DACL write failed*'
            $failure.Exception.InnerExceptions[1].Message | Should -BeLike '*Description restoration failed*'
        }
    }
}
