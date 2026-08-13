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

    Import-Module ActiveDirectory -ErrorAction Stop
    $script:shareName = 'WacLab$'
    $script:testSid = (Get-ADUser -Identity 'WacLabUser' -ErrorAction Stop).SID.Value
    $script:localUserName = 'WacSmb' + [guid]::NewGuid().ToString('N').Substring(0, 8)
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
    $moduleRoot = & (Join-Path $PSScriptRoot 'Resolve-WindowsAccessControlLabModuleRoot.ps1')
    Copy-Item `
        -Path (Join-Path $moduleRoot '*') `
        -Destination $script:remoteModulePath `
        -ToSession $script:session `
        -Recurse `
        -Force `
        -ErrorAction Stop
    $script:remoteManifest = Join-Path $script:remoteModulePath 'WindowsAccessControl.psd1'
    Import-Module `
        -Name (Join-Path $PSScriptRoot 'WindowsAccessControl.DomainLab.psm1') `
        -ErrorAction Stop
    $null = Enter-WindowsAccessControlMemberCoverage `
        -Session $script:session `
        -ModulePath (Join-Path $script:remoteModulePath 'WindowsAccessControl.psm1')
    $script:originalDescriptor = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:remoteManifest, $script:shareName `
        -ScriptBlock {
            param($Manifest, $ShareName)

            Import-Module $Manifest -Force -ErrorAction Stop
            Get-SmbShareSecurityDescriptor -Name $ShareName
        }
    $script:originalDescription = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:shareName `
        -ScriptBlock {
            param($ShareName)

            (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
        }
    $delegation = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:localUserName, $script:shareName `
        -ScriptBlock {
            param($UserName, $ShareName)

            $passwordText = 'Wac!' + [guid]::NewGuid().ToString('N') + 'aA1'
            $securePassword = [Security.SecureString]::new()
            foreach ($character in $passwordText.ToCharArray()) {
                $securePassword.AppendChar($character)
            }
            $securePassword.MakeReadOnly()
            $passwordText = $null
            $user = New-LocalUser `
                -Name $UserName `
                -Password $securePassword `
                -AccountNeverExpires `
                -PasswordNeverExpires `
                -ErrorAction Stop
            Add-LocalGroupMember `
                -Group 'Administrators' `
                -Member $user `
                -ErrorAction Stop
            $script:WacSmbCredential = [pscredential]::new(
                ".\$UserName",
                $securePassword
            )
            $module = Get-Module WindowsAccessControl
            $target = & $module {
                param($Name)
                Resolve-WindowsSmbShareTarget -Name $Name
            } $ShareName
            $current = Get-SmbShareSecurityDescriptor -Name $ShareName
            $updated = & $module {
                param($Bytes, $Sid)
                Invoke-WindowsAclRuleMutation `
                    -SecurityDescriptor $Bytes `
                    -RuleType Access `
                    -Operation Add `
                    -SecurityIdentifier $Sid `
                    -AccessMask 0x00060000 `
                    -AccessControlType Allow
            } $current.BinarySecurityDescriptor $user.SID
            & $module {
                param($Target, $Bytes, $Current)
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $Target `
                    -SecurityDescriptor $Bytes `
                    -CurrentSecurityDescriptor $Current
            } $target $updated $current.BinarySecurityDescriptor
            [pscustomobject]@{ SID = $user.SID.Value }
        }
    $script:delegatedSid = $delegation.SID
    $script:delegatedDescriptor = Invoke-Command `
        -Session $script:session `
        -ArgumentList $script:shareName `
        -ScriptBlock {
            param($ShareName)

            Get-SmbShareSecurityDescriptor -Name $ShareName
        }
}

AfterAll {
    try {
            Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:shareName, $script:originalDescriptor.Sddl, $script:originalDescription `
                -ScriptBlock {
                    param($ShareName, $Sddl, $Description)

                    Set-SmbShareSecurityDescriptor `
                        -Name $ShareName `
                        -Sddl $Sddl `
                        -Confirm:$false
                    Set-SmbShare `
                        -Name $ShareName `
                        -Description $Description `
                        -Confirm:$false
                }
            $finalSddl = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName `
            -ScriptBlock {
                param($ShareName)

                (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
            }
        if ($finalSddl -cne $script:originalDescriptor.Sddl) {
            throw 'The disposable SMB share DACL was not restored.'
        }
        $finalDescription = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName `
            -ScriptBlock {
                param($ShareName)

                (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
            }
        if ($finalDescription -cne $script:originalDescription) {
            throw 'The disposable SMB share description was not restored.'
        }
    }
    finally {
        if ($script:session) {
            Invoke-Command `
                -Session $script:session `
                -ArgumentList $script:remoteModulePath, $script:localUserName `
                -ScriptBlock {
                    param($ModulePath, $UserName)

                    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
                    Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
                    $script:WacSmbCredential = $null
                } `
                -ErrorAction SilentlyContinue
            $null = Exit-WindowsAccessControlMemberCoverage `
                -Session $script:session `
                -Name 'SmbSharePermissions.Live.Tests.ps1'
            Remove-PSSession $script:session
        }
    }
}

Describe 'SMB share DACL commands' -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    AfterEach {
        Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:delegatedDescriptor.Sddl, $script:originalDescription `
            -ScriptBlock {
                param($ShareName, $Sddl, $Description)

                Set-SmbShareSecurityDescriptor `
                    -Name $ShareName `
                    -Sddl $Sddl `
                    -Confirm:$false
                Set-SmbShare `
                    -Name $ShareName `
                    -Description $Description `
                    -Confirm:$false
            }
    }

    It 'Should return a typed DACL descriptor and deduplicate canonical share names' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName `
            -ScriptBlock {
                param($ShareName)

                Invoke-WindowsAccessControl `
                    -Credential $script:WacSmbCredential `
                    -ScriptBlock {
                        param($Name)
                        Get-SmbShareSecurityDescriptor -Name @($Name, $Name.ToUpperInvariant())
                    } `
                    -ArgumentList $ShareName
            }

        $result | Should -HaveCount 1
        $result.PSObject.TypeNames | Should -Contain 'Deserialized.WindowsAccessControl.SmbShareSecurityDescriptor'
        $result.ShareName | Should -BeExactly $script:shareName
        $result.Sections.ToString() | Should -Be 'Access'
        $result.BinarySecurityDescriptor.Count | Should -BeGreaterThan 0
    }

    It 'Should report bounded share-only effective access without an NTFS claim' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName `
            -ScriptBlock {
                param($ShareName)

                Invoke-WindowsAccessControl `
                    -Credential $script:WacSmbCredential `
                    -ScriptBlock {
                        param($Name)
                        Get-SmbShareEffectiveAccess `
                            -Name @($Name, $Name.ToUpperInvariant())
                    } `
                    -ArgumentList $ShareName
            }

        @($result) | Should -HaveCount 1
        $result.PSObject.TypeNames |
            Should -Contain 'Deserialized.WindowsAccessControl.SmbShareEffectiveAccess'
        $result.AccessMask | Should -BeGreaterThan 0
        $result.AuthorizationContext | Should -BeExactly 'LocalSidDerived'
        $result.IncludesBackingNtfs | Should -BeFalse
    }

    It 'Should honor WhatIf for descriptor and rule writes' {
        $before = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                Invoke-WindowsAccessControl `
                    -Credential $script:WacSmbCredential `
                    -ScriptBlock {
                        param($Name, $Sid)
                        $beforeSddl = (Get-SmbShareSecurityDescriptor -Name $Name).Sddl
                        Set-SmbShareSecurityDescriptor `
                            -Name $Name `
                            -Sddl 'D:(A;;0x001200A9;;;WD)' `
                            -WhatIf
                        Add-SmbShareAccessRule `
                            -Name $Name `
                            -Account $Sid `
                            -AccessRights Read `
                            -WhatIf
                        [pscustomobject]@{
                            Before = $beforeSddl
                            After = (Get-SmbShareSecurityDescriptor -Name $Name).Sddl
                            IdentitySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                            IsAdministrator = [Security.Principal.WindowsPrincipal]::new(
                                [Security.Principal.WindowsIdentity]::GetCurrent()
                            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                        }
                    } `
                    -ArgumentList $ShareName, $TestSid
            }

        $before.Before | Should -BeExactly $before.After
        $before.IdentitySid | Should -Be $script:delegatedSid
        $before.IsAdministrator | Should -BeTrue
    }

    It 'Should add and exactly remove a typed rule while preserving unrelated ACEs' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                Invoke-WindowsAccessControl `
                    -Credential $script:WacSmbCredential `
                    -ScriptBlock {
                        param($Name, $Sid)
                        $original = Get-SmbShareAccessRule -Name $Name
                        $added = Add-SmbShareAccessRule `
                            -Name $Name `
                            -Account $Sid `
                            -AccessRights Read `
                            -PassThru `
                            -Confirm:$false
                        $descriptionAfterAdd = (Get-SmbShare -Name $Name).Description
                        $afterAdd = @(Get-SmbShareAccessRule -Name $Name)
                        $removed = $added | Remove-SmbShareAccessRule -PassThru -Confirm:$false
                        $descriptionAfterRemove = (Get-SmbShare -Name $Name).Description
                        $afterRemove = @(Get-SmbShareAccessRule -Name $Name)
                        [pscustomobject]@{
                            OriginalCount = @($original).Count
                            AddedCount = $afterAdd.Count
                            FinalCount = $afterRemove.Count
                            AddedSid = $added.SID
                            AddedRights = $added.AccessRights.ToString()
                            AddedMask = $added.AccessMask
                            RemovedSid = $removed.SID
                            OriginalSids = @($original).SID
                            FinalSids = $afterRemove.SID
                            DescriptionAfterAdd = $descriptionAfterAdd
                            DescriptionAfterRemove = $descriptionAfterRemove
                        }
                    } `
                    -ArgumentList $ShareName, $TestSid
            }

        $result.AddedCount | Should -Be ($result.OriginalCount + 1)
        $result.FinalCount | Should -Be $result.OriginalCount
        $result.AddedSid | Should -Be $script:testSid
        $result.RemovedSid | Should -Be $script:testSid
        $result.AddedRights | Should -Be 'Read'
        $result.AddedMask | Should -Be 0x001200A9
        @($result.FinalSids) | Should -Be @($result.OriginalSids)
        $result.DescriptionAfterAdd | Should -BeExactly $script:originalDescription
        $result.DescriptionAfterRemove | Should -BeExactly $script:originalDescription
    }

    It 'Should reject remote syntax and administrative shares' {
        $messages = Invoke-Command -Session $script:session -ScriptBlock {
            foreach ($target in '\\server\share', 'ADMIN$', 'C$', 'IPC$', 'print$') {
                try {
                    Get-SmbShareSecurityDescriptor -Name $target -ErrorAction Stop
                }
                catch {
                    $_.Exception.GetType().FullName
                }
            }
        }

        $messages | Should -HaveCount 5
        $messages | Should -Not -Contain $null
    }

    It 'Should round trip a schema-version-2 share backup on its own computer' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                $backupPath = Join-Path $env:TEMP (
                    'wac-share-backup-{0}.json' -f [guid]::NewGuid().ToString('N')
                )
                try {
                    $before = Get-SmbShareSecurityDescriptor -Name $ShareName
                    $before | Backup-WindowsSecurityDescriptor `
                        -DestinationPath $backupPath `
                        -Confirm:$false
                    $document = Get-Content -LiteralPath $backupPath -Raw |
                        ConvertFrom-Json

                    $null = Add-SmbShareAccessRule `
                        -Name $ShareName `
                        -Account $TestSid `
                        -AccessRights Read `
                        -Confirm:$false
                    $drifted = Get-SmbShareSecurityDescriptor -Name $ShareName

                    Restore-WindowsSecurityDescriptor `
                        -BackupPath $backupPath `
                        -Confirm:$false
                    $restored = Get-SmbShareSecurityDescriptor -Name $ShareName

                    [pscustomobject]@{
                        SchemaVersion   = $document.SchemaVersion
                        RecordVersion   = $document.Records[0].RecordVersion
                        RecordServer    = $document.Records[0].Server
                        RecordShareName = $document.Records[0].ShareName
                        CanonicalTarget = $before.CanonicalTarget
                        BeforeSddl      = $before.Sddl
                        DriftedSddl     = $drifted.Sddl
                        RestoredSddl    = $restored.Sddl
                        ComputerName    = $env:COMPUTERNAME
                    }
                }
                finally {
                    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
                }
            }

        $result.SchemaVersion | Should -Be 2
        $result.RecordVersion | Should -Be 2
        $result.RecordServer | Should -BeExactly $result.ComputerName.ToUpperInvariant()
        $result.RecordShareName | Should -BeExactly $script:shareName
        $result.CanonicalTarget |
            Should -BeExactly ('SmbShare:{0}:{1}' -f
                $result.ComputerName.ToUpperInvariant(),
                $script:shareName.ToUpperInvariant())
        $result.DriftedSddl | Should -Not -BeExactly $result.BeforeSddl
        $result.RestoredSddl | Should -BeExactly $result.BeforeSddl
    }

    It 'Should converge the share descriptor and rule DSC resources' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                $module = Get-Module WindowsAccessControl
                $before = Get-SmbShareSecurityDescriptor -Name $ShareName
                try {
                    $ruleState = & $module {
                        param($Name, $Sid)

                        $resource = [WindowsAccessControlSmbShareAccessRule]::new()
                        $resource.Name = $Name
                        $resource.Account = $Sid
                        $resource.AccessRights = [WindowsSmbShareRights]::Read
                        $resource.AccessControlType =
                            [Security.AccessControl.AccessControlType]::Allow
                        $resource.Ensure = [WindowsAccessControlDscEnsure]::Present

                        $initial = $resource.Test()
                        $resource.Set()
                        $afterSet = $resource.Test()
                        $resource.Ensure = [WindowsAccessControlDscEnsure]::Absent
                        $resource.Set()
                        $afterRemove = $resource.Test()
                        [pscustomobject]@{
                            Initial     = $initial
                            AfterSet    = $afterSet
                            AfterRemove = $afterRemove
                        }
                    } $ShareName $TestSid

                    $descriptorState = & $module {
                        param($Name, $Sddl)

                        $resource = [WindowsAccessControlSmbShareSecurityDescriptor]::new()
                        $resource.Name = $Name
                        $resource.Sections = [WindowsSecurityDescriptorSection]::Access
                        $resource.Sddl = $Sddl
                        $compliant = $resource.Test()
                        $current = $resource.Get()
                        [pscustomobject]@{
                            Compliant = $compliant
                            Sddl      = $current.Sddl
                            Reasons   = @($current.Reasons).Count
                        }
                    } $ShareName $before.Sddl

                    [pscustomobject]@{
                        RuleInitial          = $ruleState.Initial
                        RuleAfterSet         = $ruleState.AfterSet
                        RuleAfterRemove      = $ruleState.AfterRemove
                        DescriptorCompliant  = $descriptorState.Compliant
                        DescriptorSddl       = $descriptorState.Sddl
                        DescriptorReasons    = $descriptorState.Reasons
                        BeforeSddl           = $before.Sddl
                        FinalSddl            = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                    }
                }
                finally {
                    Set-SmbShareSecurityDescriptor `
                        -Name $ShareName `
                        -Sddl $before.Sddl `
                        -Confirm:$false
                }
            }

        $result.RuleInitial | Should -BeFalse
        $result.RuleAfterSet | Should -BeTrue
        $result.RuleAfterRemove | Should -BeTrue
        $result.DescriptorCompliant | Should -BeTrue
        $result.DescriptorReasons | Should -Be 0
        $result.DescriptorSddl | Should -BeExactly $result.BeforeSddl
        $result.FinalSddl | Should -BeExactly $result.BeforeSddl
    }
}
