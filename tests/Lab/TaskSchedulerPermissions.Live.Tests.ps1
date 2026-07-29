[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseUsingScopeModifierInNewRunspaces',
    '',
    Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
)]
param()

BeforeAll {
    if ([string]::IsNullOrWhiteSpace($env:WAC_DOMAIN_LAB_MEMBER)) {
        throw 'WAC_DOMAIN_LAB_MEMBER must identify the disposable member server.'
    }

    $script:taskPath = '\WindowsAccessControlLab'
    $script:taskName = 'WacAcl' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $script:session = New-PSSession `
        -ComputerName $env:WAC_DOMAIN_LAB_MEMBER `
        -Authentication Kerberos `
        -ErrorAction Stop
    $script:remoteModulePath = 'C:\WindowsAccessControlLab\ModuleUnderTest'
    Invoke-Command -Session $script:session -ArgumentList $script:remoteModulePath -ScriptBlock {
        param($ModulePath)

        Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-Item -Path $ModulePath -ItemType Directory -Force
    }
    $moduleSource = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*" |
        Sort-Object -Property { [version]$_.Name } -Descending |
        Select-Object -First 1
    Copy-Item `
        -Path (Join-Path $moduleSource.FullName '*') `
        -Destination $script:remoteModulePath `
        -ToSession $script:session `
        -Recurse `
        -Force `
        -ErrorAction Stop
    $script:remoteManifest = Join-Path $script:remoteModulePath 'WindowsAccessControl.psd1'

    $script:original = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:remoteManifest, $script:taskPath, $script:taskName `
        -ScriptBlock {
            param($Manifest, $TaskPath, $TaskName)

            Import-Module $Manifest -Force -ErrorAction Stop
            $service = $null
            $folder = $null
            $definition = $null
            $registration = $null
            $settings = $null
            $principal = $null
            $actions = $null
            $action = $null
            $task = $null
            try {
                $service = New-Object -ComObject 'Schedule.Service'
                $service.Connect()
                $folder = $service.GetFolder($TaskPath)
                $definition = $service.NewTask(0)
                $registration = $definition.RegistrationInfo
                $registration.Description = 'WindowsAccessControl disposable ACL test task.'
                $settings = $definition.Settings
                $settings.Enabled = $false
                $principal = $definition.Principal
                $principal.UserId = 'SYSTEM'
                $principal.LogonType = 5
                $actions = $definition.Actions
                $action = $actions.Create(0)
                $action.Path = "$env:SystemRoot\System32\cmd.exe"
                $action.Arguments = '/c exit 0'
                $task = $folder.RegisterTaskDefinition(
                    $TaskName,
                    $definition,
                    6,
                    $null,
                    $null,
                    5,
                    $null
                )
                [pscustomobject]@{
                    FolderSddl = (Get-TaskFolderSecurityDescriptor -Path $TaskPath).Sddl
                    TaskSddl = (Get-ScheduledTaskSecurityDescriptor `
                        -TaskPath $TaskPath `
                        -TaskName $TaskName).Sddl
                    TaskXml = [string]$task.Xml
                }
            }
            finally {
                foreach ($comObject in @(
                    $task,
                    $action,
                    $actions,
                    $principal,
                    $settings,
                    $registration,
                    $definition,
                    $folder,
                    $service
                )) {
                    if ($null -ne $comObject -and
                        [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                    }
                }
            }
        }
}

AfterAll {
    try {
        if ($script:session -and $script:original) {
            $final = Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:taskPath, $script:taskName, $script:original `
                -ScriptBlock {
                    param($TaskPath, $TaskName, $Original)

                    Set-TaskFolderSecurityDescriptor `
                        -Path $TaskPath `
                        -AllowedRootPath $TaskPath `
                        -Sddl $Original.FolderSddl `
                        -Confirm:$false
                    Set-ScheduledTaskSecurityDescriptor `
                        -TaskPath $TaskPath `
                        -TaskName $TaskName `
                        -AllowedRootPath $TaskPath `
                        -Sddl $Original.TaskSddl `
                        -Confirm:$false
                    $currentFolder = Get-TaskFolderSecurityDescriptor -Path $TaskPath
                    $currentTask = Get-ScheduledTaskSecurityDescriptor `
                        -TaskPath $TaskPath `
                        -TaskName $TaskName
                    $module = Get-Module WindowsAccessControl
                    [pscustomobject]@{
                        FolderEquivalent = & $module {
                            param($OriginalSddl, $CurrentDescriptor)
                            Test-WindowsTaskSchedulerDaclEquivalent `
                                -Left ([Security.AccessControl.RawSecurityDescriptor]::new($OriginalSddl)) `
                                -Right $CurrentDescriptor
                        } $Original.FolderSddl $currentFolder.NativeDescriptor
                        TaskEquivalent = & $module {
                            param($OriginalSddl, $CurrentDescriptor)
                            Test-WindowsTaskSchedulerDaclEquivalent `
                                -Left ([Security.AccessControl.RawSecurityDescriptor]::new($OriginalSddl)) `
                                -Right $CurrentDescriptor
                        } $Original.TaskSddl $currentTask.NativeDescriptor
                    }
                }
            if (-not $final.FolderEquivalent -or -not $final.TaskEquivalent) {
                throw 'Task Scheduler live-test DACL rollback did not restore the original state.'
            }
        }
    }
    finally {
        if ($script:session) {
            Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:taskPath, $script:taskName, $script:remoteModulePath `
                -ScriptBlock {
                    param($TaskPath, $TaskName, $ModulePath)

                    $service = $null
                    $folder = $null
                    try {
                        $service = New-Object -ComObject 'Schedule.Service'
                        $service.Connect()
                        $folder = $service.GetFolder($TaskPath)
                        $folder.DeleteTask($TaskName, 0)
                    }
                    catch {
                        if ($_.Exception.HResult -ne -2147024894) {
                            Write-Warning $_.Exception.Message
                        }
                    }
                    finally {
                        foreach ($comObject in @($folder, $service)) {
                            if ($null -ne $comObject -and
                                [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                            }
                        }
                    }
                    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
                } `
                -ErrorAction SilentlyContinue
            Remove-PSSession $script:session
        }
    }
}

Describe 'Task Scheduler DACL descriptor commands' -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    AfterEach {
        Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName, $script:original `
            -ScriptBlock {
                param($TaskPath, $TaskName, $Original)

                Set-TaskFolderSecurityDescriptor `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Sddl $Original.FolderSddl `
                    -Confirm:$false
                Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName `
                    -AllowedRootPath $TaskPath `
                    -Sddl $Original.TaskSddl `
                    -Confirm:$false
            }
    }

    It 'Should return typed folder and task descriptors' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName `
            -ScriptBlock {
                param($TaskPath, $TaskName)

                [pscustomobject]@{
                    Folder = Get-TaskFolderSecurityDescriptor -Path @($TaskPath, $TaskPath.ToUpperInvariant())
                    Task = Get-ScheduledTaskSecurityDescriptor -TaskPath $TaskPath -TaskName $TaskName
                }
            }

        @($result.Folder) | Should -HaveCount 1
        $result.Folder.PSObject.TypeNames |
            Should -Contain 'Deserialized.WindowsAccessControl.TaskFolderSecurityDescriptor'
        $result.Task.PSObject.TypeNames |
            Should -Contain 'Deserialized.WindowsAccessControl.ScheduledTaskSecurityDescriptor'
        $result.Task.TaskName | Should -BeExactly $script:taskName
    }

    It 'Should honor WhatIf and reject unsafe write boundaries' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName `
            -ScriptBlock {
                param($TaskPath, $TaskName)

                $beforeFolder = (Get-TaskFolderSecurityDescriptor -Path $TaskPath).Sddl
                $beforeTask = (Get-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName).Sddl
                Set-TaskFolderSecurityDescriptor `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Sddl $beforeFolder `
                    -WhatIf
                Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName `
                    -AllowedRootPath $TaskPath `
                    -Sddl $beforeTask `
                    -WhatIf
                $rejections = @(
                    foreach ($target in '\', '\Microsoft\Windows', '\Other') {
                        try {
                            Set-TaskFolderSecurityDescriptor `
                                -Path $target `
                                -AllowedRootPath $TaskPath `
                                -Sddl $beforeFolder `
                                -Confirm:$false `
                                -ErrorAction Stop
                        }
                        catch {
                            $_.Exception.GetType().FullName
                        }
                    }
                )
                [pscustomobject]@{
                    FolderUnchanged = (Get-TaskFolderSecurityDescriptor -Path $TaskPath).Sddl -ceq $beforeFolder
                    TaskUnchanged = (Get-ScheduledTaskSecurityDescriptor `
                        -TaskPath $TaskPath `
                        -TaskName $TaskName).Sddl -ceq $beforeTask
                    Rejections = $rejections
                }
            }

        $result.FolderUnchanged | Should -BeTrue
        $result.TaskUnchanged | Should -BeTrue
        @($result.Rejections) | Should -HaveCount 3
        @($result.Rejections) | Should -Not -Contain $null
    }

    It 'Should round-trip folder and task DACLs without changing the task definition' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName `
            -ScriptBlock {
                param($TaskPath, $TaskName)

                function Add-TestAce {
                    param([string]$Sddl)

                    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
                    $descriptor.DiscretionaryAcl.InsertAce(
                        $descriptor.DiscretionaryAcl.Count,
                        [Security.AccessControl.CommonAce]::new(
                            [Security.AccessControl.AceFlags]::None,
                            [Security.AccessControl.AceQualifier]::AccessAllowed,
                            0x00020000,
                            [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                            $false,
                            $null
                        )
                    )
                    $descriptor.GetSddlForm('Access')
                }

                $service = $null
                $folder = $null
                $task = $null
                try {
                    $service = New-Object -ComObject 'Schedule.Service'
                    $service.Connect()
                    $folder = $service.GetFolder($TaskPath)
                    $task = $folder.GetTask($TaskName)
                    $xmlBefore = [string]$task.Xml
                }
                finally {
                    foreach ($comObject in @($task, $folder, $service)) {
                        if ($null -ne $comObject -and
                            [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                        }
                    }
                }

                $folderBefore = Get-TaskFolderSecurityDescriptor -Path $TaskPath
                $taskBefore = Get-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName
                $folderAfter = Set-TaskFolderSecurityDescriptor `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Sddl (Add-TestAce $folderBefore.Sddl) `
                    -PassThru `
                    -Confirm:$false
                $taskAfter = Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName `
                    -AllowedRootPath $TaskPath `
                    -Sddl (Add-TestAce $taskBefore.Sddl) `
                    -PassThru `
                    -Confirm:$false

                $service = $null
                $folder = $null
                $task = $null
                try {
                    $service = New-Object -ComObject 'Schedule.Service'
                    $service.Connect()
                    $folder = $service.GetFolder($TaskPath)
                    $task = $folder.GetTask($TaskName)
                    $xmlAfter = [string]$task.Xml
                }
                finally {
                    foreach ($comObject in @($task, $folder, $service)) {
                        if ($null -ne $comObject -and
                            [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                        }
                    }
                }

                [pscustomobject]@{
                    FolderChanged = $folderAfter.Sddl -cne $folderBefore.Sddl
                    TaskChanged = $taskAfter.Sddl -cne $taskBefore.Sddl
                    FolderSystem = $folderAfter.Sddl -match ';;;SY\)'
                    TaskSystem = $taskAfter.Sddl -match ';;;SY\)'
                    DefinitionPreserved = $xmlAfter -ceq $xmlBefore
                }
            }

        $result.FolderChanged | Should -BeTrue
        $result.TaskChanged | Should -BeTrue
        $result.FolderSystem | Should -BeTrue
        $result.TaskSystem | Should -BeTrue
        $result.DefinitionPreserved | Should -BeTrue
    }
}

Describe 'Task Scheduler typed access-rule commands' -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    AfterEach {
        Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName, $script:original `
            -ScriptBlock {
                param($TaskPath, $TaskName, $Original)

                Set-TaskFolderSecurityDescriptor `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Sddl $Original.FolderSddl `
                    -Confirm:$false
                Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName `
                    -AllowedRootPath $TaskPath `
                    -Sddl $Original.TaskSddl `
                    -Confirm:$false
            }
    }

    It 'Should emit typed folder and task rules with Task Scheduler rights' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName `
            -ScriptBlock {
                param($TaskPath, $TaskName)

                $folderRules = @(Get-TaskFolderAccessRule `
                    -Path @($TaskPath, $TaskPath.ToUpperInvariant()))
                $taskRules = @(Get-ScheduledTaskAccessRule `
                    -TaskPath $TaskPath -TaskName $TaskName)
                [pscustomobject]@{
                    FirstFolderRule = $folderRules[0]
                    FolderRightsType = $folderRules[0].AccessRights.GetType().FullName
                    FolderSystemRule = [bool]@($folderRules |
                        Where-Object { $_.SID -eq 'S-1-5-18' })
                    FolderAppliesTo = @($folderRules.AppliesTo | Sort-Object -Unique)
                    TaskCount = $taskRules.Count
                    TaskName = $taskRules[0].TaskName
                    TaskInherited = [bool]@($taskRules | Where-Object IsInherited)
                    ExplicitOnly = @(Get-TaskFolderAccessRule `
                        -Path $TaskPath -ExcludeInherited).Count
                    AllCount = $folderRules.Count
                }
            }

        $result.FirstFolderRule.PSObject.TypeNames |
            Should -Contain 'Deserialized.WindowsAccessControl.TaskFolderAccessRule'
        $result.FolderRightsType | Should -BeExactly 'WindowsTaskFolderRights'
        $result.FolderSystemRule | Should -BeTrue
        $result.FolderAppliesTo | Should -Not -Contain 'Custom'
        $result.TaskCount | Should -BeGreaterThan 0
        $result.TaskName | Should -BeExactly $script:taskName
        $result.TaskInherited | Should -BeTrue
        $result.ExplicitOnly | Should -BeLessOrEqual $result.AllCount
    }

    It 'Should add and exactly remove typed rules while preserving unrelated ACEs' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:taskPath, $script:taskName `
            -ScriptBlock {
                param($TaskPath, $TaskName)

                $folderBefore = (Get-TaskFolderSecurityDescriptor -Path $TaskPath).Sddl
                $taskBefore = (Get-ScheduledTaskSecurityDescriptor `
                    -TaskPath $TaskPath -TaskName $TaskName).Sddl

                Add-TaskFolderAccessRule `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Account 'S-1-1-0' `
                    -AccessRights ReadAndTraverse `
                    -AppliesTo ThisFolderSubfoldersAndTasks `
                    -WhatIf
                $whatIfFolder = (Get-TaskFolderSecurityDescriptor -Path $TaskPath).Sddl

                $addedFolder = @(Add-TaskFolderAccessRule `
                    -Path $TaskPath `
                    -AllowedRootPath $TaskPath `
                    -Account 'S-1-1-0', 'S-1-1-0' `
                    -AccessRights ReadAndTraverse `
                    -AppliesTo ThisFolderSubfoldersAndTasks `
                    -PassThru `
                    -Confirm:$false)
                $addedTask = @(Add-ScheduledTaskAccessRule `
                    -TaskPath $TaskPath `
                    -TaskName $TaskName `
                    -AllowedRootPath $TaskPath `
                    -Account 'S-1-1-0' `
                    -AccessRights Read `
                    -PassThru `
                    -Confirm:$false)

                $removedFolder = $addedFolder |
                    Remove-TaskFolderAccessRule `
                        -AllowedRootPath $TaskPath -PassThru -Confirm:$false
                $removedTask = $addedTask |
                    Remove-ScheduledTaskAccessRule `
                        -AllowedRootPath $TaskPath -PassThru -Confirm:$false

                $inheritedRule = @(Get-ScheduledTaskAccessRule `
                    -TaskPath $TaskPath -TaskName $TaskName -ExcludeExplicit)[0]
                $inheritedRejected = $null
                try {
                    Remove-ScheduledTaskAccessRule `
                        -InputObject $inheritedRule `
                        -AllowedRootPath $TaskPath `
                        -Confirm:$false `
                        -ErrorAction Stop
                }
                catch {
                    $inheritedRejected = $_.Exception.Message
                }

                $lockoutRejected = $null
                try {
                    Add-TaskFolderAccessRule `
                        -Path $TaskPath `
                        -AllowedRootPath $TaskPath `
                        -Account 'S-1-1-0' `
                        -AccessRights FullControl `
                        -AccessControlType Deny `
                        -Confirm:$false `
                        -ErrorAction Stop
                }
                catch {
                    $lockoutRejected = $_.Exception.Message
                }

                [pscustomobject]@{
                    WhatIfUnchanged = $whatIfFolder -ceq $folderBefore
                    AddedFolderCount = $addedFolder.Count
                    AddedFolderRights = [string]$addedFolder[0].AccessRights
                    AddedFolderAppliesTo = $addedFolder[0].AppliesTo
                    AddedTaskCount = $addedTask.Count
                    RemovedFolderSid = $removedFolder.SID
                    RemovedTaskSid = $removedTask.SID
                    FolderRestored = (Get-TaskFolderSecurityDescriptor `
                        -Path $TaskPath).Sddl -ceq $folderBefore
                    TaskRestored = (Get-ScheduledTaskSecurityDescriptor `
                        -TaskPath $TaskPath -TaskName $TaskName).Sddl -ceq $taskBefore
                    InheritedRejected = $inheritedRejected
                    LockoutRejected = $lockoutRejected
                }
            }

        $result.WhatIfUnchanged | Should -BeTrue
        $result.AddedFolderCount | Should -Be 1
        $result.AddedFolderRights | Should -BeExactly 'ReadAndTraverse'
        $result.AddedFolderAppliesTo | Should -BeExactly 'ThisFolderSubfoldersAndTasks'
        $result.AddedTaskCount | Should -Be 1
        $result.RemovedFolderSid | Should -BeExactly 'S-1-1-0'
        $result.RemovedTaskSid | Should -BeExactly 'S-1-1-0'
        $result.FolderRestored | Should -BeTrue
        $result.TaskRestored | Should -BeTrue
        $result.InheritedRejected | Should -BeLike '*inherited*'
        $result.LockoutRejected | Should -BeLike '*Task Scheduler service token*'
    }
}