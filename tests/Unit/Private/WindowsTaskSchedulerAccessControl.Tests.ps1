BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Task Scheduler access-control internals' -Tag 'Unit', 'WindowsOnly' {
    It 'Should normalize a contained scheduled-task target' {
        $target = & $script:module {
            Resolve-WindowsTaskSchedulerTarget `
                -Path '\WindowsAccessControlLab' `
                -TaskName 'Fixture' `
                -ForWrite `
                -AllowedRootPath '\WindowsAccessControlLab'
        }

        $target.ObjectType | Should -BeExactly 'ScheduledTask'
        $target.TaskPath | Should -BeExactly '\WindowsAccessControlLab'
        $target.TaskName | Should -BeExactly 'Fixture'
        $target.CanonicalTarget | Should -BeExactly (
            'ScheduledTask:Local:\WINDOWSACCESSCONTROLLAB\FIXTURE'
        )
    }

    It 'Should reject unsafe or out-of-bound write targets before COM activation' {
        $cases = @(
            @{ Path = '\'; AllowedRoot = '\WindowsAccessControlLab' }
            @{ Path = '\Microsoft\Windows'; AllowedRoot = '\Microsoft' }
            @{ Path = '\Other'; AllowedRoot = '\WindowsAccessControlLab' }
            @{ Path = '\WindowsAccessControlLab\..\Other'; AllowedRoot = '\WindowsAccessControlLab' }
            @{ Path = '\\server\Folder'; AllowedRoot = '\WindowsAccessControlLab' }
        )

        foreach ($case in $cases) {
            {
                & $script:module {
                    param($Path, $AllowedRoot)
                    Resolve-WindowsTaskSchedulerTarget `
                        -Path $Path `
                        -ForWrite `
                        -AllowedRootPath $AllowedRoot
                } $case.Path $case.AllowedRoot
            } | Should -Throw -ExpectedMessage '*Task Scheduler*'
        }
    }

    It 'Should release task, folder, and service objects in reverse order' {
        & $script:module {
            $script:releaseOrder = [Collections.Generic.List[string]]::new()
            $script:fakeTask = [pscustomobject]@{ Name = 'Fixture' }
            $script:fakeFolder = [pscustomobject]@{ Path = '\WindowsAccessControlLab' }
            $script:fakeFolder | Add-Member ScriptMethod GetTask {
                param($Name)
                $null = $Name
                $script:fakeTask
            }
            $script:fakeService = [pscustomobject]@{ Name = 'Service' }
            $script:fakeService | Add-Member ScriptMethod Connect { }
            $script:fakeService | Add-Member ScriptMethod GetFolder {
                param($Path)
                $null = $Path
                $script:fakeFolder
            }
            Mock New-WindowsTaskSchedulerService { $script:fakeService }
            Mock Close-WindowsTaskSchedulerComObject {
                param($InputObject)
                $objectName = if ($InputObject -eq $script:fakeTask) {
                    'Task'
                }
                elseif ($InputObject -eq $script:fakeFolder) {
                    'Folder'
                }
                else {
                    'Service'
                }
                $script:releaseOrder.Add($objectName)
            }

            $target = Resolve-WindowsTaskSchedulerTarget `
                -Path '\WindowsAccessControlLab' `
                -TaskName 'Fixture'
            {
                Invoke-WindowsTaskSchedulerComOperation `
                    -Target $target `
                    -Operation { throw 'Expected operation failure.' }
            } | Should -Throw -ExpectedMessage '*Expected operation failure*'

            $script:releaseOrder | Should -Be @('Task', 'Folder', 'Service')
        }
    }

    It 'Should preserve SYSTEM ACEs and use object-specific setter flags' {
        & $script:module {
            $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
            $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $current = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)'
            )
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)'
            )
            $currentBytes = [byte[]]::new($current.BinaryLength)
            $current.GetBinaryForm($currentBytes, 0)
            $candidateBytes = [byte[]]::new($candidate.BinaryLength)
            $candidate.GetBinaryForm($candidateBytes, 0)
            $script:setFlags = [Collections.Generic.List[int]]::new()
            $script:storedSddl = $current.GetSddlForm('Access')
            $script:fakeNative = [pscustomobject]@{}
            $script:fakeNative | Add-Member ScriptMethod GetSecurityDescriptor {
                param($Information)
                $null = $Information
                $script:storedSddl
            }
            $script:fakeNative | Add-Member ScriptMethod SetSecurityDescriptor {
                param($Sddl, $Flags)
                $script:setFlags.Add($Flags)
                $script:storedSddl = $Sddl
            }
            Mock Invoke-WindowsTaskSchedulerComOperation {
                param($Target, $Operation)
                $null = $Target
                & $Operation $script:fakeNative
            }

            foreach ($objectType in 'TaskFolder', 'ScheduledTask') {
                $target = [pscustomobject]@{
                    ObjectType = $objectType
                    CanonicalTarget = "$objectType`:Local:\WINDOWSACCESSCONTROLLAB"
                }
                $null = Set-WindowsTaskSchedulerSecurityDescriptor `
                    -Target $target `
                    -SecurityDescriptor $candidateBytes
                $script:storedSddl = $current.GetSddlForm('Access')
            }

            $script:setFlags | Should -Be @(0, 16)
            $systemSid.Value | Should -Be 'S-1-5-18'
            $administratorsSid.Value | Should -Be 'S-1-5-32-544'
        }
    }

    It 'Should reject a candidate that removes the current SYSTEM ACE' {
        & $script:module {
            $script:currentDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)'
            )
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;BA)'
            )
            $candidateBytes = [byte[]]::new($candidate.BinaryLength)
            $candidate.GetBinaryForm($candidateBytes, 0)
            $script:fakeNative = [pscustomobject]@{}
            $script:fakeNative | Add-Member ScriptMethod GetSecurityDescriptor {
                param($Information)
                $null = $Information
                $script:currentDescriptor.GetSddlForm('Access')
            }
            $script:fakeNative | Add-Member ScriptMethod SetSecurityDescriptor {
                throw 'Setter must not run.'
            }
            Mock Invoke-WindowsTaskSchedulerComOperation {
                param($Target, $Operation)
                $null = $Target
                & $Operation $script:fakeNative
            }

            {
                Set-WindowsTaskSchedulerSecurityDescriptor `
                    -Target ([pscustomobject]@{ ObjectType = 'TaskFolder' }) `
                    -SecurityDescriptor $candidateBytes
            } | Should -Throw -ExpectedMessage '*SYSTEM ACE*'
        }
    }

    It 'Should treat reordered identical ACEs as equivalent but reject rights changes' {
        $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;RC;;;WD)'
        )
        $reordered = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:AI(A;;RC;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)'
        )
        $changed = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;FW;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)'
        )

        & $script:module {
            param($Left, $Right)
            Test-WindowsTaskSchedulerDaclEquivalent -Left $Left -Right $Right
        } $candidate $reordered | Should -BeTrue
        & $script:module {
            param($Left, $Right)
            Test-WindowsTaskSchedulerDaclEquivalent -Left $Left -Right $Right
        } $candidate $changed | Should -BeFalse
    }
}