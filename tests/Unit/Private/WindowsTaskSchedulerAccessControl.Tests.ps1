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
        $target.Server | Should -BeExactly ([Environment]::MachineName.ToUpperInvariant())
        $target.CanonicalTarget | Should -BeExactly (
            'ScheduledTask:{0}:\WINDOWSACCESSCONTROLLAB\FIXTURE' -f
                [Environment]::MachineName.ToUpperInvariant()
        )
    }

    It 'Should reject a task name that normalizes to nothing' {
        {
            & $script:module {
                Resolve-WindowsTaskSchedulerTarget `
                    -Path '\WindowsAccessControlLab' `
                    -TaskName '   '
            }
        } | Should -Throw -ExpectedMessage '*is not a canonical local name*'
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

    It 'Should map the Task Scheduler rights model onto the documented file masks' {
        [int][WindowsTaskFolderRights]::ListTasks | Should -Be 0x00000001
        [int][WindowsTaskFolderRights]::CreateTask | Should -Be 0x00000002
        [int][WindowsTaskFolderRights]::CreateSubfolder | Should -Be 0x00000004
        [int][WindowsTaskFolderRights]::Traverse | Should -Be 0x00000020
        [int][WindowsTaskFolderRights]::ChangePermissions | Should -Be 0x00040000
        [int][WindowsTaskFolderRights]::ReadAndTraverse | Should -Be 0x001200A9
        [int][WindowsTaskFolderRights]::FullControl | Should -Be 0x001F01FF

        [int][WindowsScheduledTaskRights]::ReadTaskDefinition | Should -Be 0x00000001
        [int][WindowsScheduledTaskRights]::WriteTaskDefinition | Should -Be 0x00000002
        [int][WindowsScheduledTaskRights]::RunTask | Should -Be 0x00000020
        [int][WindowsScheduledTaskRights]::Read | Should -Be 0x00120089
        [int][WindowsScheduledTaskRights]::ReadAndRun | Should -Be 0x001200A9
        [int][WindowsScheduledTaskRights]::Write | Should -Be 0x00120116
        [int][WindowsScheduledTaskRights]::Modify | Should -Be 0x001301BF
        [int][WindowsScheduledTaskRights]::FullControl | Should -Be 0x001F01FF
    }

    It 'Should keep container-only and SACL rights off the leaf-task surface' {
        $taskMembers = [enum]::GetNames([WindowsScheduledTaskRights])

        $taskMembers | Should -Not -Contain 'CreateSubfolder'
        $taskMembers | Should -Not -Contain 'DeleteChild'
        $taskMembers | Should -Not -Contain 'AccessSystemSecurity'
        [enum]::GetNames([WindowsTaskFolderRights]) |
            Should -Not -Contain 'AccessSystemSecurity'
        [string][System.Enum]::ToObject([WindowsScheduledTaskRights], 0x6) |
            Should -BeExactly '6' -Because 'a leaf task has no name for an inherited folder-only bit'
        [string][System.Enum]::ToObject([WindowsScheduledTaskRights], 0x001F019F) |
            Should -Not -BeExactly '2032031' -Because 'a real inherited task mask must still decompose'
    }

    It 'Should add an ACE that differs only by inheritance scope' {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;0x1200a9;;;WD)'
        )
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)

        $result = & $script:module {
            param($Bytes)
            Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $Bytes `
                -RuleType Access `
                -Operation Add `
                -SecurityIdentifier ([Security.Principal.SecurityIdentifier]::new('S-1-1-0')) `
                -AccessMask 0x001200A9 `
                -AceFlags ([Security.AccessControl.AceFlags]'ObjectInherit, ContainerInherit') `
                -MatchAceFlags
        } $bytes
        $suppressed = & $script:module {
            param($Bytes)
            Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $Bytes `
                -RuleType Access `
                -Operation Add `
                -SecurityIdentifier ([Security.Principal.SecurityIdentifier]::new('S-1-1-0')) `
                -AccessMask 0x001200A9 `
                -MatchAceFlags
        } $bytes

        ([Security.AccessControl.RawSecurityDescriptor]::new(
            $result, 0)).DiscretionaryAcl.Count | Should -Be 2
        ([Security.AccessControl.RawSecurityDescriptor]::new(
            $suppressed, 0)).DiscretionaryAcl.Count | Should -Be 1
    }

    It 'Should convert every folder inheritance scope to exact ACE flags' {
        $expected = @{
            ThisFolderOnly               = 0
            ThisFolderAndTasks           = 1
            ThisFolderAndSubfolders      = 2
            ThisFolderSubfoldersAndTasks = 3
            TasksOnly                    = 9
            SubfoldersOnly               = 10
            SubfoldersAndTasksOnly       = 11
        }

        foreach ($appliesTo in $expected.Keys) {
            $flags = & $script:module {
                param($AppliesTo)
                ConvertTo-WindowsTaskSchedulerAceFlag -AppliesTo $AppliesTo
            } $appliesTo
            [int]$flags | Should -Be $expected[$appliesTo] -Because "$appliesTo maps to one exact flag set"
        }
    }

    It 'Should reject a new deny ACE that could lock out the service token' {
        $current = [Security.AccessControl.RawSecurityDescriptor]::new('D:(A;;FA;;;SY)')
        $lockouts = @(
            'D:(A;;FA;;;SY)(D;;FR;;;BU)'
            'D:(A;;FA;;;SY)(D;;GA;;;WD)'
            'D:(A;;FA;;;SY)(D;;FA;;;BA)'
            'D:(A;;FA;;;SY)(D;;FX;;;SU)'
        )
        $harmless = @(
            'D:(A;;FA;;;SY)(D;;WO;;;BU)'
            'D:(A;;FA;;;SY)(D;;FA;;;S-1-5-21-1-2-3-1000)'
        )

        foreach ($sddl in $lockouts) {
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
            & $script:module {
                param($Current, $Candidate)
                Test-WindowsTaskSchedulerServiceDenyAce `
                    -CurrentDescriptor $Current -CandidateDescriptor $Candidate
            } $current $candidate | Should -BeTrue -Because "$sddl denies the service token"
        }
        foreach ($sddl in $harmless) {
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
            & $script:module {
                param($Current, $Candidate)
                Test-WindowsTaskSchedulerServiceDenyAce `
                    -CurrentDescriptor $Current -CandidateDescriptor $Candidate
            } $current $candidate | Should -BeFalse -Because "$sddl leaves the service token intact"
        }
    }

    It 'Should keep managing a target that already carries a service-token deny ACE' {
        $current = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(D;;FR;;;BU)(A;;FA;;;SY)'
        )
        $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(D;;FR;;;BU)(A;;FA;;;SY)(A;;FR;;;AU)'
        )

        & $script:module {
            param($Current, $Candidate)
            Test-WindowsTaskSchedulerServiceDenyAce `
                -CurrentDescriptor $Current -CandidateDescriptor $Candidate
        } $current $candidate | Should -BeFalse
    }

    It 'Should reject object ACEs that the store would silently re-revision' {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new('D:(A;;FA;;;SY)')
        $objectAce = [Security.AccessControl.ObjectAce]::new(
            [Security.AccessControl.AceFlags]::None,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            0x00120089,
            [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
            [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
            [guid]'11111111-2222-3333-4444-555555555555',
            [guid]::Empty,
            $false,
            $null)
        $descriptor.DiscretionaryAcl.InsertAce(0, $objectAce)

        {
            & $script:module {
                param($Descriptor)
                Assert-WindowsTaskSchedulerAceSupport -SecurityDescriptor $Descriptor
            } $descriptor
        } | Should -Throw -ExpectedMessage '*only common ACEs*'
    }

    It 'Should stop a service-token lockout at the persistence boundary' {
        & $script:module {
            $script:currentDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)'
            )
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)(D;;FA;;;BU)'
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
            } | Should -Throw -ExpectedMessage '*Task Scheduler service token*'
        }
    }

    It 'Should reject a write whose target changed after the staging read' {
        & $script:module {
            $script:currentDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)'
            )
            $stale = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)'
            )
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)'
            )
            $staleBytes = [byte[]]::new($stale.BinaryLength)
            $stale.GetBinaryForm($staleBytes, 0)
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
                    -SecurityDescriptor $candidateBytes `
                    -ExpectedCurrentSecurityDescriptor $staleBytes
            } | Should -Throw -ExpectedMessage '*changed after it was read*'
        }
    }

    It 'Should report an indeterminate state when rollback cannot be verified' {
        & $script:module {
            $script:storedSddl = 'D:(A;;FA;;;SY)(A;;FA;;;BA)'
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)'
            )
            $candidateBytes = [byte[]]::new($candidate.BinaryLength)
            $candidate.GetBinaryForm($candidateBytes, 0)
            $script:fakeNative = [pscustomobject]@{}
            $script:fakeNative | Add-Member ScriptMethod GetSecurityDescriptor {
                param($Information)
                $null = $Information
                $script:storedSddl
            }
            $script:fakeNative | Add-Member ScriptMethod SetSecurityDescriptor {
                param($Sddl, $Flags)
                $null = $Sddl
                $null = $Flags
                $script:storedSddl = 'D:(A;;FA;;;SY)'
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
            } | Should -Throw -ExpectedMessage '*indeterminate*'
        }
    }

    It 'Should warn about a deny ACE that blocks future DACL management' {
        $warnings = & $script:module {
            $current = [Security.AccessControl.RawSecurityDescriptor]::new('D:(A;;FA;;;SY)')
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(D;;WDWO;;;BU)'
            )
            Write-WindowsTaskSchedulerDenyAceWarning `
                -CurrentDescriptor $current `
                -CandidateDescriptor $candidate `
                -WarningAction SilentlyContinue `
                -WarningVariable captured
            $captured
        }

        [string]$warnings | Should -BeLike '*change the DACL or owner*'
    }
}