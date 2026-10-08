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

# FR-18, FR-21, NFR-11, NFR-14: local share writes and explicitly share-only Authz results.
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

# FR-18, NFR-11: a DACL write keeps the share description. The native write clears it and the
# command restores it, a concurrent edit is kept with a warning, and a description that cannot
# be read before the write stops the command before anything is written.
Describe 'SMB share description around a DACL write' -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    BeforeAll {
        # Native share calls the module does not make: a DACL-only SE_LMSHARE
        # write, and a watcher that edits the description as soon as the DACL
        # changes, before the setter reads the description back.
        $shareNativeSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace WindowsAccessControlLab
{
    public static class SmbShareNative
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ShareInfo502
        {
            public IntPtr NetName;
            public int Type;
            public IntPtr Remark;
            public int Permissions;
            public int MaxUses;
            public int CurrentUses;
            public IntPtr Path;
            public IntPtr Password;
            public int Reserved;
            public IntPtr SecurityDescriptor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ShareInfo1004
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Remark;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareGetInfo(string serverName, string netName, int level, out IntPtr buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareSetInfo(string serverName, string netName, int level, ref ShareInfo1004 buffer, out int parameterError);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll")]
        private static extern int GetSecurityDescriptorLength(IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
        private static extern int SetNamedSecurityInfo(string objectName, int objectType, int securityInformation, IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);

        public static byte[] ReadSecurityDescriptor(string shareName)
        {
            IntPtr buffer;
            int status = NetShareGetInfo(null, shareName, 502, out buffer);
            if (status != 0)
            {
                throw new Win32Exception(status);
            }
            try
            {
                ShareInfo502 info = (ShareInfo502)Marshal.PtrToStructure(buffer, typeof(ShareInfo502));
                if (info.SecurityDescriptor == IntPtr.Zero)
                {
                    return new byte[0];
                }
                int length = GetSecurityDescriptorLength(info.SecurityDescriptor);
                byte[] bytes = new byte[length];
                Marshal.Copy(info.SecurityDescriptor, bytes, 0, length);
                return bytes;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }

        public static void SetRemark(string shareName, string remark)
        {
            ShareInfo1004 info = new ShareInfo1004();
            info.Remark = remark;
            int parameterError;
            int status = NetShareSetInfo(null, shareName, 1004, ref info, out parameterError);
            if (status != 0)
            {
                throw new Win32Exception(status);
            }
        }

        // SE_LMSHARE (5) with DACL_SECURITY_INFORMATION (4) only.
        public static void WriteDacl(string shareName, byte[] dacl)
        {
            int status = SetNamedSecurityInfo(shareName, 5, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (status != 0)
            {
                throw new Win32Exception(status);
            }
        }

        public static long SetRemarkWhenGranted(string shareName, byte[] sid, string remark, int timeoutMilliseconds, ManualResetEventSlim ready, CancellationToken cancellation)
        {
            Stopwatch watch = Stopwatch.StartNew();
            long nextPoll = 0;
            try
            {
                while (watch.ElapsedMilliseconds < timeoutMilliseconds && !cancellation.IsCancellationRequested)
                {
                    // One read per millisecond keeps the watcher well inside the
                    // read-back window without flooding the server service.
                    while (watch.ElapsedTicks < nextPoll)
                    {
                        Thread.SpinWait(20);
                    }
                    nextPoll = watch.ElapsedTicks + Stopwatch.Frequency / 1000;
                    byte[] current = ReadSecurityDescriptor(shareName);
                    ready.Set();
                    if (Contains(current, sid))
                    {
                        SetRemark(shareName, remark);
                        return watch.ElapsedMilliseconds;
                    }
                }
                return -1;
            }
            finally
            {
                ready.Set();
            }
        }

        private static bool Contains(byte[] data, byte[] pattern)
        {
            for (int start = 0; start + pattern.Length <= data.Length; start++)
            {
                int index = 0;
                while (index < pattern.Length && data[start + index] == pattern[index])
                {
                    index++;
                }
                if (index == pattern.Length)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
'@
        Invoke-Command `
            -Session $script:session `
            -ArgumentList $shareNativeSource `
            -ScriptBlock {
                param($Source)

                if (-not ('WindowsAccessControlLab.SmbShareNative' -as [type])) {
                    Add-Type -TypeDefinition $Source -ErrorAction Stop
                }
            }
    }

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

    It 'Should restore a description that the native DACL write cleared' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid, $script:originalDescription `
            -ScriptBlock {
                param($ShareName, $TestSid, $Description)

                # Without the module, writing the unchanged DACL natively is
                # enough to clear the description.
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                    [WindowsAccessControlLab.SmbShareNative]::ReadSecurityDescriptor($ShareName),
                    0
                )
                $dacl = [byte[]]::new($descriptor.DiscretionaryAcl.BinaryLength)
                $descriptor.DiscretionaryAcl.GetBinaryForm($dacl, 0)
                [WindowsAccessControlLab.SmbShareNative]::WriteDacl($ShareName, $dacl)
                $nativeDescription = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
                Set-SmbShare `
                    -Name $ShareName `
                    -Description $Description `
                    -Confirm:$false `
                    -ErrorAction Stop

                $outcome = Invoke-WindowsAccessControl `
                    -Credential $script:WacSmbCredential `
                    -ScriptBlock {
                        param($Name, $Sid)

                        $stream = @(Add-SmbShareAccessRule `
                            -Name $Name `
                            -Account $Sid `
                            -AccessRights Read `
                            -PassThru `
                            -Confirm:$false `
                            -Verbose 4>&1)
                        [pscustomobject]@{
                            AddedSid = @($stream | Where-Object {
                                $_ -isnot [Management.Automation.VerboseRecord]
                            })[0].SID
                            Restorations = @($stream | Where-Object {
                                $_ -is [Management.Automation.VerboseRecord] -and
                                $_.Message -like 'Restored the description*'
                            } | ForEach-Object { $_.Message })
                            Description = (Get-SmbShare -Name $Name -ErrorAction Stop).Description
                        }
                    } `
                    -ArgumentList $ShareName, $TestSid
                [pscustomobject]@{
                    NativeDescription = $nativeDescription
                    AddedSid = $outcome.AddedSid
                    Restorations = $outcome.Restorations
                    Description = $outcome.Description
                }
            }

        $result.NativeDescription | Should -BeNullOrEmpty
        $result.AddedSid | Should -BeExactly $script:testSid
        @($result.Restorations) | Should -Be @(
            "Restored the description of SMB share '{0}' to '{1}' after the DACL write cleared it." -f
                $script:shareName, $script:originalDescription
        )
        $result.Description | Should -BeExactly $script:originalDescription
    }

    It 'Should keep a description edited during the DACL write and warn with the earlier value' {
        $attempts = @(Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid, $script:originalDescription, $script:delegatedDescriptor.Sddl `
            -ScriptBlock {
                param($ShareName, $TestSid, $Description, $DelegatedSddl)

                $sid = [Security.Principal.SecurityIdentifier]::new($TestSid)
                $sidBytes = [byte[]]::new($sid.BinaryLength)
                $sid.GetBinaryForm($sidBytes, 0)
                # The native write publishes the grant and clears the
                # description in one step, and the setter reads the description
                # back some milliseconds later through CIM. A watcher that fires
                # on that grant edits the description inside this window. When
                # it is descheduled past the setter's read-back, the restore
                # replaces its edit and no warning is due, so the write is
                # retried, up to five writes.
                foreach ($attempt in 1..5) {
                    Set-SmbShare `
                        -Name $ShareName `
                        -Description $Description `
                        -Confirm:$false `
                        -ErrorAction Stop
                    if (@(Get-SmbShareAccessRule -Name $ShareName | Where-Object { $_.SID -eq $TestSid }).Count) {
                        throw 'The share already grants the test identity, so the watcher cannot detect the write.'
                    }
                    $editedDescription = 'WindowsAccessControl lab concurrent edit {0}' -f $attempt
                    $ready = [Threading.ManualResetEventSlim]::new($false)
                    $cancellation = [Threading.CancellationTokenSource]::new()
                    $watcher = [powershell]::Create()
                    $warnings = @()
                    $watcherElapsed = -1
                    try {
                        # The watcher fires on the grant this add writes, not on
                        # any byte change, so it cannot edit the description
                        # before the setter reads it.
                        $null = $watcher.AddScript({
                            param($Name, $Sid, $Remark, $Ready, $Token)

                            [WindowsAccessControlLab.SmbShareNative]::SetRemarkWhenGranted(
                                $Name,
                                $Sid,
                                $Remark,
                                60000,
                                $Ready,
                                $Token
                            )
                        }).AddArgument($ShareName).
                            AddArgument($sidBytes).
                            AddArgument($editedDescription).
                            AddArgument($ready).
                            AddArgument($cancellation.Token)
                        $pending = $watcher.BeginInvoke()
                        if (-not $ready.Wait(30000)) {
                            throw 'The description watcher did not start.'
                        }
                        # Invoke-WindowsAccessControl returns $null when its
                        # script block returns nothing.
                        $warnings = @(@(Invoke-WindowsAccessControl `
                            -Credential $script:WacSmbCredential `
                            -ScriptBlock {
                                param($Name, $Sid)

                                Add-SmbShareAccessRule `
                                    -Name $Name `
                                    -Account $Sid `
                                    -AccessRights Read `
                                    -Confirm:$false 3>&1 |
                                    Where-Object { $_ -is [Management.Automation.WarningRecord] } |
                                    ForEach-Object { $_.Message }
                            } `
                            -ArgumentList $ShareName, $TestSid) | Where-Object { $null -ne $_ })
                        $watcherElapsed = @($watcher.EndInvoke($pending))[0]
                    }
                    finally {
                        $cancellation.Cancel()
                        $watcher.Dispose()
                        $cancellation.Dispose()
                        $ready.Dispose()
                    }
                    $finalDescription = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
                    # An unchanged DACL would make the next add a no-op.
                    Set-SmbShareSecurityDescriptor `
                        -Name $ShareName `
                        -Sddl $DelegatedSddl `
                        -Confirm:$false
                    [pscustomobject]@{
                        Attempt = $attempt
                        EditedDescription = $editedDescription
                        WatcherElapsedMs = $watcherElapsed
                        Warnings = $warnings
                        FinalDescription = $finalDescription
                    }
                    if ($warnings.Count -gt 0) {
                        break
                    }
                }
            })

        $last = $attempts[-1]
        $because = 'the attempts were {0}' -f (
            $attempts |
                Select-Object -Property Attempt, WatcherElapsedMs, FinalDescription, Warnings |
                ConvertTo-Json -Depth 3 -Compress
        )
        @($last.Warnings) | Should -Be @(
            ("The description of SMB share '{0}' changed while its DACL was written and was left as it is. " +
                "The description before the write was '{1}'.") -f
                $script:shareName, $script:originalDescription
        ) -Because $because
        $last.FinalDescription | Should -BeExactly $last.EditedDescription -Because $because
        @($attempts | Where-Object { $_.WatcherElapsedMs -lt 0 }) | Should -BeNullOrEmpty -Because $because
    }

    It 'Should stop before writing when the description cannot be read before the write' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                # Target resolution reads the share twice just before the setter
                # does, so no live condition fails only the setter's own read. A
                # module-scope shadow of Get-SmbShare injects that one failure
                # and passes every other call to the real command.
                $module = Get-Module -Name WindowsAccessControl
                $sddlBefore = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                $descriptionBefore = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
                $failure = $null
                $reads = @()
                try {
                    & $module {
                        $script:WacLabShareReads = [Collections.Generic.List[string]]::new()
                        ${function:script:Get-SmbShare} = {
                            [CmdletBinding()]
                            param(
                                [Parameter(Position = 0)]
                                [string[]]$Name
                            )

                            $caller = (Get-PSCallStack)[1].Command
                            $script:WacLabShareReads.Add($caller)
                            if ($caller -eq 'Set-WindowsSmbShareSecurityDescriptor' -and
                                @($script:WacLabShareReads | Where-Object { $_ -eq $caller }).Count -eq 1) {
                                throw [UnauthorizedAccessException]::new(
                                    'WindowsAccessControl lab injected failure: the share description could not be read.'
                                )
                            }
                            SmbShare\Get-SmbShare @PSBoundParameters
                        }
                    }
                    try {
                        Invoke-WindowsAccessControl `
                            -Credential $script:WacSmbCredential `
                            -ScriptBlock {
                                param($Name, $Sid)

                                Add-SmbShareAccessRule `
                                    -Name $Name `
                                    -Account $Sid `
                                    -AccessRights Read `
                                    -Confirm:$false `
                                    -ErrorAction Stop
                            } `
                            -ArgumentList $ShareName, $TestSid
                    }
                    catch {
                        # -ErrorAction Stop turns the error into an
                        # ActionPreferenceStopException whose ErrorRecord, not
                        # its InnerException, holds the original exception.
                        $exception = $_.Exception
                        for ($depth = 0; $depth -lt 10 -and $exception; $depth++) {
                            if ($exception -is [Management.Automation.ActionPreferenceStopException] -and
                                $exception.ErrorRecord -and
                                -not [object]::ReferenceEquals($exception.ErrorRecord.Exception, $exception)) {
                                $exception = $exception.ErrorRecord.Exception
                            }
                            elseif ($exception.InnerException) {
                                $exception = $exception.InnerException
                            }
                            else {
                                break
                            }
                        }
                        $failure = '{0}: {1}' -f $exception.GetType().FullName, $exception.Message
                    }
                    $reads = & $module { $script:WacLabShareReads.ToArray() }
                }
                finally {
                    & $module {
                        $shadow = Get-Command -Name Get-SmbShare -CommandType Function
                        if ($shadow.ModuleName -eq 'WindowsAccessControl') {
                            Remove-Item -LiteralPath 'Function:\Get-SmbShare'
                        }
                        Remove-Variable -Name WacLabShareReads -Scope Script -ErrorAction SilentlyContinue
                    }
                }
                [pscustomobject]@{
                    Failure = $failure
                    Reads = $reads
                    ShadowRemoved = [string](& $module { (Get-Command -Name Get-SmbShare).ModuleName }) -eq 'SmbShare'
                    DaclUnchanged = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl -ceq $sddlBefore
                    GrantPresent = [bool]@(
                        Get-SmbShareAccessRule -Name $ShareName | Where-Object { $_.SID -eq $TestSid }
                    ).Count
                    DescriptionUnchanged = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description -ceq
                        $descriptionBefore
                }
            }

        $result.Failure | Should -BeExactly (
            'System.UnauthorizedAccessException: ' +
            'WindowsAccessControl lab injected failure: the share description could not be read.'
        )
        @($result.Reads) | Should -Be @(
            'Resolve-WindowsSmbShareTarget'
            'Resolve-WindowsSmbShareTarget'
            'Set-WindowsSmbShareSecurityDescriptor'
        )
        $result.DaclUnchanged | Should -BeTrue
        $result.GrantPresent | Should -BeFalse
        $result.DescriptionUnchanged | Should -BeTrue
        $result.ShadowRemoved | Should -BeTrue
    }
}

# FR-18, NFR-11: refusals and the confirmation that keep an unintended share
# write from happening, and the descriptor a write reports.
Describe 'SMB share DACL command guards' -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
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

    It 'Should refuse an SDDL without a DACL before writing' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName `
            -ScriptBlock {
                param($ShareName)

                $sddlBefore = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                # No DACL section at all, and a DACL section that is present
                # but null, which would grant everyone full access.
                $failures = foreach ($sddl in 'O:BA', 'D:NO_ACCESS_CONTROL') {
                    try {
                        Set-SmbShareSecurityDescriptor `
                            -Name $ShareName `
                            -Sddl $sddl `
                            -Confirm:$false `
                            -ErrorAction Stop
                        'no failure'
                    }
                    catch {
                        $_.Exception.Message
                    }
                }
                [pscustomobject]@{
                    Failures = @($failures)
                    Unchanged = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl -ceq $sddlBefore
                }
            }

        @($result.Failures) | Should -Be @(
            'The supplied SDDL does not contain a non-null DACL.'
            'The supplied SDDL does not contain a non-null DACL.'
        )
        $result.Unchanged | Should -BeTrue
    }

    It 'Should return the stored descriptor with PassThru' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                $requested = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl +
                    "(A;;0x1200a9;;;$TestSid)"
                $output = @(
                    Set-SmbShareSecurityDescriptor `
                        -Name $ShareName `
                        -Sddl $requested `
                        -PassThru `
                        -Confirm:$false
                )
                [pscustomobject]@{
                    Requested = $requested
                    Output = $output
                    Stored = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                    Description = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
                }
            }

        @($result.Output) | Should -HaveCount 1
        $result.Output[0].PSObject.TypeNames |
            Should -Contain 'Deserialized.WindowsAccessControl.SmbShareSecurityDescriptor'
        $result.Output[0].ShareName | Should -BeExactly $script:shareName
        $result.Output[0].Sections.ToString() | Should -Be 'Access'
        $result.Output[0].Sddl | Should -BeExactly $result.Stored
        $result.Stored | Should -BeExactly $result.Requested
        $result.Description | Should -BeExactly $script:originalDescription
    }

    It 'Should refuse a rule copy that was not read from the share before removing anything' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                $added = Add-SmbShareAccessRule `
                    -Name $ShareName `
                    -Account $TestSid `
                    -AccessRights Read `
                    -PassThru `
                    -Confirm:$false
                $sddlBefore = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                # A rule restored from serialized data and a reshaped copy keep
                # the rule's values but are no longer the object the share
                # returned.
                $copies = @(
                    [Management.Automation.PSSerializer]::Deserialize(
                        [Management.Automation.PSSerializer]::Serialize($added)
                    )
                    $added | Select-Object -Property *
                )
                $failures = foreach ($copy in $copies) {
                    try {
                        $copy | Remove-SmbShareAccessRule -Confirm:$false -ErrorAction Stop
                        'no failure'
                    }
                    catch {
                        $_.Exception.Message
                    }
                }
                [pscustomobject]@{
                    Failures = @($failures)
                    Unchanged = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl -ceq $sddlBefore
                    StillGranted = [bool]@(
                        Get-SmbShareAccessRule -Name $ShareName | Where-Object { $_.SID -eq $TestSid }
                    ).Count
                }
            }

        @($result.Failures) | Should -Be @(
            'InputObject must be a path-bound rule from Get-SmbShareAccessRule.'
            'InputObject must be a path-bound rule from Get-SmbShareAccessRule.'
        )
        $result.Unchanged | Should -BeTrue
        $result.StillGranted | Should -BeTrue
    }

    It 'Should refuse a rule whose canonical target names another server' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:shareName, $script:testSid `
            -ScriptBlock {
                param($ShareName, $TestSid)

                $added = Add-SmbShareAccessRule `
                    -Name $ShareName `
                    -Account $TestSid `
                    -AccessRights Read `
                    -PassThru `
                    -Confirm:$false
                $sddlBefore = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                $readTarget = $added.CanonicalTarget
                $added.CanonicalTarget = 'SmbShare:WACLABOTHER:{0}' -f $ShareName.ToUpperInvariant()
                $failure = try {
                    $added | Remove-SmbShareAccessRule -Confirm:$false -ErrorAction Stop
                    'no failure'
                }
                catch {
                    $_.Exception.Message
                }
                [pscustomobject]@{
                    ReadTarget = $readTarget
                    Server = [Environment]::MachineName.ToUpperInvariant()
                    Failure = $failure
                    Unchanged = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl -ceq $sddlBefore
                    StillGranted = [bool]@(
                        Get-SmbShareAccessRule -Name $ShareName | Where-Object { $_.SID -eq $TestSid }
                    ).Count
                }
            }

        $result.ReadTarget | Should -BeExactly (
            'SmbShare:{0}:{1}' -f $result.Server, $script:shareName.ToUpperInvariant()
        )
        $result.Failure | Should -BeExactly 'The SMB share rule target no longer matches its canonical identity.'
        $result.Unchanged | Should -BeTrue
        $result.StillGranted | Should -BeTrue
    }

    It 'Should ask before writing and write nothing when the caller cannot answer' {
        # Without -Confirm:$false the high-impact write asks the caller first.
        # A remote prompt goes to the host of the runspace that opened the
        # session, so a session opened from a runspace without a user interface
        # answers it with an error in every host, and this case never waits on
        # a person. Such a session also starts with remote debugging off, which
        # the coverage breakpoints armed in it need.
        $opener = [powershell]::Create()
        $promptless = $null
        $coverageArmed = $false
        try {
            $null = $opener.AddCommand('New-PSSession').
                AddParameter('ComputerName', $env:WAC_DOMAIN_LAB_MEMBER).
                AddParameter('Authentication', 'Kerberos').
                AddParameter('ErrorAction', 'Stop')
            $promptless = @($opener.Invoke())[0]
            $promptless.Runspace.Debugger.SetDebugMode(
                [System.Management.Automation.DebugModes]'LocalScript, RemoteScript'
            )
            Invoke-Command `
                -Session $promptless `
                -ArgumentList $script:remoteManifest `
                -ScriptBlock {
                    param($Manifest)

                    Import-Module $Manifest -Force -ErrorAction Stop
                }
            $null = Enter-WindowsAccessControlMemberCoverage `
                -Session $promptless `
                -ModulePath (Join-Path $script:remoteModulePath 'WindowsAccessControl.psm1')
            $coverageArmed = $true
            $result = Invoke-Command `
                -Session $promptless `
                -ArgumentList $script:shareName, $script:testSid `
                -ScriptBlock {
                    param($ShareName, $TestSid)

                    $sddlBefore = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl
                    $descriptionBefore = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description
                    # The call states the default Continue preference under
                    # which the refusal is reported, so the case does not
                    # depend on the preference of the session it runs in.
                    $stream = @(
                        Set-SmbShareSecurityDescriptor `
                            -Name $ShareName `
                            -Sddl ($sddlBefore + "(A;;0x1200a9;;;$TestSid)") `
                            -ErrorAction Continue 2>&1
                    )
                    $failures = @($stream | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
                    [pscustomobject]@{
                        ConfirmPreference = [string]$ConfirmPreference
                        OutputCount = $stream.Count - $failures.Count
                        Failures = @(
                            $failures | ForEach-Object {
                                $exception = $_.Exception
                                while ($exception.InnerException) {
                                    $exception = $exception.InnerException
                                }
                                '{0}: {1}' -f $exception.GetType().FullName, $exception.Message
                            }
                        )
                        Target = 'SmbShare:{0}:{1}' -f
                            [Environment]::MachineName.ToUpperInvariant(), $ShareName.ToUpperInvariant()
                        DaclUnchanged = (Get-SmbShareSecurityDescriptor -Name $ShareName).Sddl -ceq $sddlBefore
                        DescriptionUnchanged = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Description -ceq
                            $descriptionBefore
                    }
                }
        }
        finally {
            if ($promptless) {
                if ($coverageArmed) {
                    $null = Exit-WindowsAccessControlMemberCoverage `
                        -Session $promptless `
                        -Name 'SmbSharePermissions.Live.Tests.Confirmation.ps1'
                }
                Remove-PSSession -Session $promptless
            }
            $opener.Dispose()
        }

        $result.ConfirmPreference | Should -BeExactly 'High'
        $result.OutputCount | Should -Be 0
        @($result.Failures) | Should -HaveCount 1
        $result.Failures[0] | Should -BeLike 'System.Management.Automation.Host.HostException: *'
        $result.Failures[0] | Should -Match ([regex]::Escape(
            'Performing the operation "Set SMB share DACL" on target "{0}".' -f $result.Target
        ))
        $result.DaclUnchanged | Should -BeTrue
        $result.DescriptionUnchanged | Should -BeTrue
    }
}
