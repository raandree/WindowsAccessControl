BeforeAll {
    $script:moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $script:moduleManifest.FullName -ErrorAction Stop
    $null = Get-WindowsPrivilege

    $script:testId = [guid]::NewGuid().ToString('N')
    $script:registryProviderPath = "HKCU:\Software\WindowsAccessControlTest\$script:testId"
    $script:registryNativePath = "CURRENT_USER\Software\WindowsAccessControlTest\$script:testId"
    $script:serviceName = "WacTest$script:testId"
    $script:isAdministrator = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $null = New-Item -Path $script:registryProviderPath -Force -ErrorAction Stop
}

AfterAll {
    if ($script:isAdministrator -and $script:serviceName) {
        & sc.exe delete $script:serviceName 2>&1 | Out-Null
    }
    if ($script:registryProviderPath) {
        $removeParameters = @{
            LiteralPath = $script:registryProviderPath
            Recurse     = $true
            Force       = $true
            ErrorAction = 'SilentlyContinue'
        }
        Remove-Item @removeParameters
    }
    $testRoot = 'HKCU:\Software\WindowsAccessControlTest'
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $children = @(Get-ChildItem -LiteralPath $testRoot -ErrorAction SilentlyContinue)
        if ($children.Count -eq 0) {
            Remove-Item -LiteralPath $testRoot -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Windows security descriptor engine' -Tag 'Integration', 'WindowsOnly' {
    It 'Should expose public descriptor and domain rights enums' {
        ([System.Management.Automation.PSTypeName]'WindowsSecurityDescriptorSection').Type |
            Should -Not -BeNullOrEmpty
        ([System.Management.Automation.PSTypeName]'WindowsRegistryView').Type |
            Should -Not -BeNullOrEmpty
        ([System.Management.Automation.PSTypeName]'WindowsServiceRights').Type |
            Should -Not -BeNullOrEmpty
        ([System.Management.Automation.PSTypeName]'WindowsServiceControlManagerRights').Type |
            Should -Not -BeNullOrEmpty
        ([System.Management.Automation.PSTypeName]'WindowsProcessRights').Type |
            Should -Not -BeNullOrEmpty
        [uint64]([int64][WindowsServiceRights]::GenericRead -band 0xFFFFFFFFL) |
            Should -Be 2147483648
        [int][WindowsServiceRights]::AllAccess | Should -Be 0x000F01FF
        [int][WindowsServiceControlManagerRights]::AllAccess | Should -Be 0x000F003F
        [int][WindowsProcessRights]::AllAccess | Should -Be 0x001FFFFF
    }

    It 'Should replace a foreign accelerator and remove only its owned types on unload' {
        # The load and unload cycle runs in a child process. Re-importing the
        # module in this one compiles it a second time whenever the read misses
        # the engine script-block cache, and every module-defined type would
        # then exist twice for the rest of the run.
        $job = Start-Job -ScriptBlock {
            param($ManifestPath)

            $accelerators = [psobject].Assembly.GetType(
                'System.Management.Automation.TypeAccelerators'
            )
            $accelerators::Add('WindowsRegistryView', [string])

            Import-Module -Name $ManifestPath -ErrorAction Stop
            $replacement = $accelerators::Get['WindowsRegistryView']

            Remove-Module -Name 'WindowsAccessControl' -Force

            [pscustomobject]@{
                ReplacedForeignAccelerator = $replacement -ne [string]
                ReplacementTypeName = $replacement.FullName
                RemovedOwnAcceleratorOnUnload =
                    -not $accelerators::Get.ContainsKey('WindowsRegistryView')
            }
        } -ArgumentList $script:moduleManifest.FullName

        try {
            Wait-Job -Job $job -Timeout 120 | Should -Not -BeNullOrEmpty
            $result = Receive-Job -Job $job -ErrorAction Stop

            $result.ReplacedForeignAccelerator | Should -BeTrue -Because (
                "the accelerator still resolves to '$($result.ReplacementTypeName)'"
            )
            $result.RemovedOwnAcceleratorOnUnload | Should -BeTrue
        } finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should read and round-trip a named registry key DACL' {
        $sections = 1 -bor 2 -bor 4
        $beforeBytes = [WindowsAccessControl.NativeMethods]::GetNamedSecurityDescriptor(
            $script:registryNativePath,
            4,
            $sections
        )
        $before = [System.Security.AccessControl.RawSecurityDescriptor]::new($beforeBytes, 0)

        [WindowsAccessControl.NativeMethods]::SetNamedSecurityDescriptor(
            $script:registryNativePath,
            4,
            4,
            $beforeBytes
        )

        $afterBytes = [WindowsAccessControl.NativeMethods]::GetNamedSecurityDescriptor(
            $script:registryNativePath,
            4,
            $sections
        )
        $after = [System.Security.AccessControl.RawSecurityDescriptor]::new($afterBytes, 0)
        $beforeAcl = [byte[]]::new($before.DiscretionaryAcl.BinaryLength)
        $afterAcl = [byte[]]::new($after.DiscretionaryAcl.BinaryLength)
        $before.DiscretionaryAcl.GetBinaryForm($beforeAcl, 0)
        $after.DiscretionaryAcl.GetBinaryForm($afterAcl, 0)
        [Convert]::ToBase64String($beforeAcl) |
            Should -BeExactly ([Convert]::ToBase64String($afterAcl))
        $protectedFlag = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
        ($before.ControlFlags -band $protectedFlag) |
            Should -Be ($after.ControlFlags -band $protectedFlag)
    }

    It 'Should reject malformed and absent DACL descriptors before persistence' {
        {
            [WindowsAccessControl.NativeMethods]::SetNamedSecurityDescriptor(
                $script:registryNativePath,
                4,
                4,
                [byte[]]@(1, 2, 3)
            )
        } | Should -Throw -ExpectedMessage '*structurally valid*'

        $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $descriptorWithoutDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            [System.Security.AccessControl.ControlFlags]::SelfRelative,
            $owner,
            $owner,
            $null,
            $null
        )
        $descriptorBytes = [byte[]]::new($descriptorWithoutDacl.BinaryLength)
        $descriptorWithoutDacl.GetBinaryForm($descriptorBytes, 0)

        {
            [WindowsAccessControl.NativeMethods]::SetNamedSecurityDescriptor(
                $script:registryNativePath,
                4,
                4,
                $descriptorBytes
            )
        } | Should -Throw -ExpectedMessage '*non-null DACL*'
    }

    It 'Should read a named service descriptor' {
        if (-not $script:isAdministrator) {
            Set-ItResult -Skipped -Because 'Creating a disposable service requires elevation.'
            return
        }
        $binaryPath = "$env:SystemRoot\System32\cmd.exe /c exit 0"
        $output = & sc.exe create $script:serviceName 'binPath=' $binaryPath 'start=' 'demand' 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Disposable service creation failed: $output"
        }

        $descriptor = [WindowsAccessControl.NativeMethods]::GetNamedSecurityDescriptor(
            $script:serviceName,
            2,
            7
        )

        $descriptor.Length | Should -BeGreaterThan 0
        { [System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0) } |
            Should -Not -Throw
    }

    It 'Should pin a process by creation identity when reading its descriptor' {
        $process = Get-Process -Id $PID
        $creationTime = $process.StartTime.ToFileTimeUtc()

        $descriptor = [WindowsAccessControl.NativeMethods]::GetProcessSecurityDescriptor(
            $PID,
            $creationTime,
            7
        )

        $descriptor.Length | Should -BeGreaterThan 0
        {
            [WindowsAccessControl.NativeMethods]::GetProcessSecurityDescriptor(
                $PID,
                $creationTime + 1,
                7
            )
        } | Should -Throw -ExpectedMessage '*creation identity*'
        {
            [WindowsAccessControl.NativeMethods]::GetProcessSecurityDescriptor(
                $PID,
                0,
                7
            )
        } | Should -Throw -ExpectedMessage '*positive process creation identity*'
    }

    It 'Should read a caller-owned process handle without closing it' {
        $process = Get-Process -Id $PID
        try {
            $descriptor = [WindowsAccessControl.NativeMethods]::GetHandleSecurityDescriptor(
                $process.Handle,
                6,
                7
            )

            $descriptor.Length | Should -BeGreaterThan 0
            $process.HasExited | Should -BeFalse
        } finally {
            $process.Dispose()
        }
    }
}
