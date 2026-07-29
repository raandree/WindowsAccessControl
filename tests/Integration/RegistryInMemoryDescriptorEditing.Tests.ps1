BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'In-memory registry descriptor editing' -Tag 'Integration', 'WindowsOnly' {
    BeforeEach {
        $script:testKey = 'HKCU:\Software\WindowsAccessControlTest\{0}' -f [guid]::NewGuid().ToString('N')
        $null = New-Item -Path $script:testKey -Force
    }

    AfterEach {
        Remove-Item -LiteralPath $script:testKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Should stage an access rule in memory and persist it only with Set' {
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9201'

        $descriptor = Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access
        $edited = $descriptor | Add-RegistryKeyAccessRule -Account $stagedSid -AccessRights ReadKey

        Get-RegistryKeyAccessRule -Path $script:testKey -Account $stagedSid -ExcludeInherited |
            Should -BeNullOrEmpty

        $edited | Set-RegistryKeySecurityDescriptor -Confirm:$false

        $persisted = @(
            Get-RegistryKeyAccessRule -Path $script:testKey -Account $stagedSid -ExcludeInherited
        )
        $persisted | Should -HaveCount 1
    }

    It 'Should not persist a staged edit under WhatIf' {
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9202'

        Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access |
            Add-RegistryKeyAccessRule -Account $stagedSid -AccessRights ReadKey |
            Set-RegistryKeySecurityDescriptor -WhatIf

        Get-RegistryKeyAccessRule -Path $script:testKey -Account $stagedSid -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should persist several staged edits with one write' {
        $keptSid = 'S-1-5-21-1111111111-2222222222-3333333333-9203'
        $replacedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9204'

        Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access |
            Add-RegistryKeyAccessRule -Account $keptSid -AccessRights ReadKey |
            Add-RegistryKeyAccessRule -Account $replacedSid -AccessRights ReadKey |
            Set-RegistryKeyAccessRule -Account $replacedSid -AccessRights FullControl |
            Set-RegistryKeySecurityDescriptor -Confirm:$false

        @(Get-RegistryKeyAccessRule -Path $script:testKey -Account $keptSid -ExcludeInherited) |
            Should -HaveCount 1
        $replaced = @(
            Get-RegistryKeyAccessRule -Path $script:testKey -Account $replacedSid -ExcludeInherited
        )
        $replaced | Should -HaveCount 1
        $replaced[0].AccessRights | Should -Match 'FullControl'
    }

    It 'Should add and persist one rule through a bounded editing scope' {
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9205'

        $result = Edit-RegistryKeySecurityDescriptor `
            -Path $script:testKey `
            -Sections Access `
            -ScriptBlock {
                param($descriptor, $sid)
                $descriptor | Add-RegistryKeyAccessRule `
                    -Account $sid `
                    -AccessRights ReadKey | Out-Null
            } `
            -ArgumentList $stagedSid `
            -PassThru `
            -Confirm:$false

        $result.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.RegistryKeySecurityDescriptor'
        @(Get-RegistryKeyAccessRule -Path $script:testKey -Account $stagedSid -ExcludeInherited) |
            Should -HaveCount 1
    }

    It 'Should leave the target unchanged when the bounded callback fails' {
        $before = (Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access).Sddl

        {
            Edit-RegistryKeySecurityDescriptor `
                -Path $script:testKey `
                -Sections Access `
                -ScriptBlock { throw 'Expected bounded edit failure.' } `
                -Confirm:$false `
                -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*Expected bounded edit failure*'

        (Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access).Sddl |
            Should -BeExactly $before
    }

    It 'Should persist descriptor-staged inheritance protection' {
        Edit-RegistryKeySecurityDescriptor `
            -Path $script:testKey `
            -Sections Access `
            -ScriptBlock {
                param($descriptor)
                $descriptor | Disable-RegistryKeyInheritance `
                    -Section Access `
                    -PreserveInherited $true | Out-Null
            } `
            -Confirm:$false

        (Get-RegistryKeyInheritance -Path $script:testKey -Section Access).AccessInheritanceEnabled |
            Should -BeFalse
    }

    It 'Should reject staging a section the descriptor did not load' {
        $before = (Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access).Sddl

        {
            Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access |
                Add-RegistryKeyAuditRule `
                    -Account 'S-1-1-0' `
                    -AccessRights SetValue `
                    -AuditFlags Success `
                    -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*without the Audit section*'

        (Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access).Sddl |
            Should -BeExactly $before
    }

    It 'Should reject a stale descriptor when RequireUnchanged is set' {
        $staleSid = 'S-1-5-21-1111111111-2222222222-3333333333-9206'
        $concurrentSid = 'S-1-5-21-1111111111-2222222222-3333333333-9207'

        $descriptor = Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access |
            Add-RegistryKeyAccessRule -Account $staleSid -AccessRights ReadKey

        Add-RegistryKeyAccessRule `
            -Path $script:testKey `
            -Account $concurrentSid `
            -AccessRights ReadKey `
            -Confirm:$false

        {
            $descriptor | Set-RegistryKeySecurityDescriptor `
                -RequireUnchanged `
                -Confirm:$false `
                -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*changed after they were read*'

        Get-RegistryKeyAccessRule -Path $script:testKey -Account $staleSid -ExcludeInherited |
            Should -BeNullOrEmpty
        @(Get-RegistryKeyAccessRule -Path $script:testKey -Account $concurrentSid -ExcludeInherited) |
            Should -HaveCount 1
    }

    It 'Should persist an unchanged descriptor when RequireUnchanged is set' {
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9208'

        Get-RegistryKeySecurityDescriptor -Path $script:testKey -Sections Access |
            Add-RegistryKeyAccessRule -Account $stagedSid -AccessRights ReadKey |
            Set-RegistryKeySecurityDescriptor -RequireUnchanged -Confirm:$false

        @(Get-RegistryKeyAccessRule -Path $script:testKey -Account $stagedSid -ExcludeInherited) |
            Should -HaveCount 1
    }
}
