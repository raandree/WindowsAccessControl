# Differential oracle: compare what the module writes against what icacls reads
# back (FR-31). Only bracketed tokens are matched, never localized prose.
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # Nothing resolves this identifier, so denying it cannot lock the test out.
    $script:inertSid = 'S-1-5-21-1999999999-2999999999-3999999999-4321'

    function script:Get-IcaclsEntry {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $output = @(& icacls.exe $Path 2>&1 | ForEach-Object { [string]$_ })
        foreach ($line in $output) {
            foreach ($match in [regex]::Matches(
                    $line,
                    '(?<principal>[^\s:]+(?:\\[^\s:]+)*):(?<tokens>(?:\([^)]*\))+)')) {
                [pscustomobject]@{
                    Principal = $match.Groups['principal'].Value
                    Tokens    = @([regex]::Matches(
                            $match.Groups['tokens'].Value,
                            '\(([^)]*)\)'
                        ) | ForEach-Object { $_.Groups[1].Value })
                }
            }
        }
    }

    function script:Get-IcaclsEntryForSid {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [string]$Sid
        )

        $account = $null
        try {
            $account = ([System.Security.Principal.SecurityIdentifier]::new($Sid)).Translate(
                [System.Security.Principal.NTAccount]
            ).Value
        } catch [System.Security.Principal.IdentityNotMappedException] {
            $account = $null
        }

        @(Get-IcaclsEntry -Path $Path | Where-Object {
                $_.Principal -eq $Sid -or ($account -and $_.Principal -eq $account)
            })
    }

    function script:Get-InheritanceToken {
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Entry
        )

        @($Entry.Tokens | Where-Object { $_ -in @('I', 'OI', 'CI', 'IO', 'NP') } | Sort-Object)
    }

    function script:New-OracleDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $path = Join-Path -Path $TestDrive -ChildPath $Name
        $null = New-Item -Path $path -ItemType Directory -Force
        $path
    }

    function script:Test-IcaclsVerify {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        # A finding is printed as "<path>: <localized reason>". A clean run never
        # puts a colon directly after the path, so the shape is matched instead
        # of the prose.
        $output = @(& icacls.exe $Path /verify 2>&1 | ForEach-Object { [string]$_ })
        $findingPattern = '^' + [regex]::Escape($Path) + '\s*:'
        -not @($output | Where-Object { $_ -match $findingPattern })
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'NTFS icacls differential oracle' -Tag 'Integration', 'WindowsOnly' {
    Context 'Inheritance and propagation flag matrix' {
        It 'Should write <AppliesTo> as the inheritance tokens <Expected>' -ForEach @(
            @{ AppliesTo = 'ThisFolderOnly'; Expected = @() }
            @{ AppliesTo = 'ThisFolderSubfoldersAndFiles'; Expected = @('CI', 'OI') }
            @{ AppliesTo = 'ThisFolderAndSubfolders'; Expected = @('CI') }
            @{ AppliesTo = 'ThisFolderAndFiles'; Expected = @('OI') }
            @{ AppliesTo = 'SubfoldersAndFilesOnly'; Expected = @('CI', 'IO', 'OI') }
            @{ AppliesTo = 'SubfoldersOnly'; Expected = @('CI', 'IO') }
            @{ AppliesTo = 'FilesOnly'; Expected = @('IO', 'OI') }
            @{ AppliesTo = 'ThisFolderSubfoldersAndFilesOneLevel'; Expected = @('CI', 'NP', 'OI') }
            @{ AppliesTo = 'ThisFolderAndSubfoldersOneLevel'; Expected = @('CI', 'NP') }
            @{ AppliesTo = 'ThisFolderAndFilesOneLevel'; Expected = @('NP', 'OI') }
            @{ AppliesTo = 'SubfoldersAndFilesOnlyOneLevel'; Expected = @('CI', 'IO', 'NP', 'OI') }
            @{ AppliesTo = 'SubfoldersOnlyOneLevel'; Expected = @('CI', 'IO', 'NP') }
            @{ AppliesTo = 'FilesOnlyOneLevel'; Expected = @('IO', 'NP', 'OI') }
        ) {
            $path = New-OracleDirectory -Name ('allow-' + $AppliesTo)
            $addParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = $AppliesTo
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            $entries = Get-IcaclsEntryForSid -Path $path -Sid $script:inertSid
            $entries | Should -HaveCount 1
            (Get-InheritanceToken -Entry $entries) | Should -Be ($Expected | Sort-Object)
        }

        It 'Should write a deny <AppliesTo> as the inheritance tokens <Expected>' -ForEach @(
            @{ AppliesTo = 'ThisFolderOnly'; Expected = @() }
            @{ AppliesTo = 'ThisFolderSubfoldersAndFiles'; Expected = @('CI', 'OI') }
            @{ AppliesTo = 'SubfoldersAndFilesOnlyOneLevel'; Expected = @('CI', 'IO', 'NP', 'OI') }
        ) {
            $path = New-OracleDirectory -Name ('deny-' + $AppliesTo)
            $addParameters = @{
                LiteralPath       = $path
                Account           = $script:inertSid
                AccessRights      = 'Modify'
                AccessControlType = 'Deny'
                AppliesTo         = $AppliesTo
                Confirm           = $false
            }

            Add-NTFSAccessRule @addParameters

            $entries = Get-IcaclsEntryForSid -Path $path -Sid $script:inertSid
            $entries | Should -HaveCount 1
            (Get-InheritanceToken -Entry $entries) | Should -Be ($Expected | Sort-Object)
            @($entries.Tokens) | Should -Contain 'DENY'
        }

        It 'Should place a deny before an existing allow for the same principal' {
            $path = New-OracleDirectory -Name 'deny-after-allow'
            $commonParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @commonParameters
            Add-NTFSAccessRule @commonParameters -AccessControlType Deny

            $entries = @(Get-IcaclsEntry -Path $path | Where-Object Principal -EQ $script:inertSid)
            $entries | Should -HaveCount 2
            @($entries[0].Tokens) | Should -Contain 'DENY'
            @($entries[1].Tokens) | Should -Not -Contain 'DENY'
            (Get-NTFSItemSecurityDescriptor -LiteralPath $path).AccessRulesCanonical |
                Should -BeTrue
            Test-IcaclsVerify -Path $path | Should -BeTrue
        }
    }

    Context 'Generic rights' {
        It 'Should keep <Label> on the item and let icacls render the mapped rights' -ForEach @(
            @{ Label = 'GENERIC_ALL'; Mask = [uint32]0x10000000; IcaclsRight = 'F' }
            @{
                Label       = 'GENERIC_READ, GENERIC_WRITE and GENERIC_EXECUTE with DELETE'
                Mask        = [uint32]3758161920
                IcaclsRight = 'M'
            }
        ) {
            $path = New-OracleDirectory -Name ('generic-' + $IcaclsRight)
            $addParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = $Mask
                AppliesTo    = 'SubfoldersAndFilesOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:inertSid -ExcludeInherited)
            $rules | Should -HaveCount 1
            $rules[0].AccessMask | Should -Be $Mask

            # icacls applies the file system generic mapping when it renders a
            # mask, so it never prints GA, GR, GW or GE for an NTFS object even
            # though the stored mask still carries those bits.
            $entries = Get-IcaclsEntryForSid -Path $path -Sid $script:inertSid
            $entries | Should -HaveCount 1
            @($entries.Tokens) | Should -Contain $IcaclsRight
            @($entries.Tokens) | Should -Not -Contain 'GA'
        }
    }

    Context 'Synchronize normalization' {
        It 'Should add Synchronize to an allow rule for Modify' {
            $path = New-OracleDirectory -Name 'sync-allow'
            $addParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters

            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:inertSid -ExcludeInherited)
            ($rules[0].AccessMask -band
                [uint32][int][System.Security.AccessControl.FileSystemRights]::Synchronize) |
                Should -Be ([uint32][int][System.Security.AccessControl.FileSystemRights]::Synchronize)
        }

        It 'Should exclude Synchronize from a deny rule for Modify' {
            $path = New-OracleDirectory -Name 'sync-deny'
            $addParameters = @{
                LiteralPath       = $path
                Account           = $script:inertSid
                AccessRights      = 'Modify'
                AccessControlType = 'Deny'
                AppliesTo         = 'ThisFolderOnly'
                Confirm           = $false
            }

            Add-NTFSAccessRule @addParameters

            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:inertSid -ExcludeInherited)
            ($rules[0].AccessMask -band
                [uint32][int][System.Security.AccessControl.FileSystemRights]::Synchronize) |
                Should -Be 0
        }

        It 'Should keep Synchronize on a deny rule for FullControl' {
            # The framework carves FullControl out of the deny normalization, so
            # the bit survives there and only there.
            $path = New-OracleDirectory -Name 'sync-deny-full'
            $addParameters = @{
                LiteralPath       = $path
                Account           = $script:inertSid
                AccessRights      = 'FullControl'
                AccessControlType = 'Deny'
                AppliesTo         = 'ThisFolderOnly'
                Confirm           = $false
            }

            Add-NTFSAccessRule @addParameters

            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:inertSid -ExcludeInherited)
            ($rules[0].AccessMask -band
                [uint32][int][System.Security.AccessControl.FileSystemRights]::Synchronize) |
                Should -Be ([uint32][int][System.Security.AccessControl.FileSystemRights]::Synchronize)
        }

        It 'Should never make an allow and a deny for the same principal compare equal' {
            $path = New-OracleDirectory -Name 'sync-compare'
            $commonParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = 'ThisFolderOnly'
                Confirm      = $false
            }

            Add-NTFSAccessRule @commonParameters
            Add-NTFSAccessRule @commonParameters -AccessControlType Deny

            $rules = @(Get-NTFSAccessRule -LiteralPath $path -Account $script:inertSid -ExcludeInherited)
            $rules | Should -HaveCount 2
            $rules[0].AccessMask | Should -Not -Be $rules[1].AccessMask
        }
    }

    Context 'Noncanonical list on write' {
        It 'Should store a noncanonical list unchanged and report it as noncanonical' {
            $path = New-OracleDirectory -Name 'noncanonical'
            $security = Get-Acl -LiteralPath $path
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                $security.GetSecurityDescriptorBinaryForm(),
                0
            )
            $allowAce = [System.Security.AccessControl.CommonAce]::new(
                'None',
                'AccessAllowed',
                0x1F01FF,
                [System.Security.Principal.SecurityIdentifier]::new($script:inertSid),
                $false,
                $null
            )
            $denyAce = [System.Security.AccessControl.CommonAce]::new(
                'None',
                'AccessDenied',
                0x1F01FF,
                [System.Security.Principal.SecurityIdentifier]::new($script:inertSid),
                $false,
                $null
            )
            $raw.DiscretionaryAcl.InsertAce(0, $allowAce)
            $raw.DiscretionaryAcl.InsertAce(1, $denyAce)
            $binaryForm = [byte[]]::new($raw.BinaryLength)
            $raw.GetBinaryForm($binaryForm, 0)
            $security.SetSecurityDescriptorBinaryForm(
                $binaryForm,
                [System.Security.AccessControl.AccessControlSections]::Access
            )
            Set-Acl -LiteralPath $path -AclObject $security

            $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $path

            # Windows stores the list as written: it neither reorders it nor
            # protects it, so the noncanonical state has to be observable.
            $descriptor.AccessRulesCanonical | Should -BeFalse
            $descriptor.AccessRulesProtected | Should -BeFalse
            Test-NTFSItemAcl -LiteralPath $path -Section Access | Should -BeFalse
            Test-IcaclsVerify -Path $path | Should -BeFalse
        }
    }

    Context 'Automatic propagation' {
        It 'Should reach pre-existing children and be withdrawn from them' {
            $root = New-OracleDirectory -Name 'propagation'
            $child = Join-Path -Path $root -ChildPath 'child'
            $grandchild = Join-Path -Path $child -ChildPath 'grandchild'
            $null = New-Item -Path $grandchild -ItemType Directory -Force
            $ruleParameters = @{
                LiteralPath  = $root
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = 'ThisFolderSubfoldersAndFiles'
                Confirm      = $false
            }

            Add-NTFSAccessRule @ruleParameters

            foreach ($descendant in $child, $grandchild) {
                $inherited = @(
                    Get-NTFSAccessRule -LiteralPath $descendant -Account $script:inertSid |
                        Where-Object IsInherited
                )
                $inherited | Should -HaveCount 1
                @((Get-IcaclsEntryForSid -Path $descendant -Sid $script:inertSid).Tokens) |
                    Should -Contain 'I'
            }

            Remove-NTFSAccessRule @ruleParameters -RemovalMode Exact

            foreach ($descendant in $child, $grandchild) {
                @(Get-NTFSAccessRule -LiteralPath $descendant -Account $script:inertSid) |
                    Should -BeNullOrEmpty
                Get-IcaclsEntryForSid -Path $descendant -Sid $script:inertSid |
                    Should -BeNullOrEmpty
            }
        }
    }

    Context 'Verification and round trip' {
        It 'Should write only lists that icacls verifies without a finding' {
            $path = New-OracleDirectory -Name 'verify'
            $child = Join-Path -Path $path -ChildPath 'child'
            $null = New-Item -Path $child -ItemType Directory -Force
            $addParameters = @{
                LiteralPath  = $path
                Account      = $script:inertSid
                AccessRights = 'Modify'
                AppliesTo    = 'ThisFolderSubfoldersAndFiles'
                Confirm      = $false
            }

            Add-NTFSAccessRule @addParameters
            $denyParameters = @{
                LiteralPath       = $path
                Account           = $script:inertSid
                AccessRights      = 'Write'
                AccessControlType = 'Deny'
                AppliesTo         = 'ThisFolderSubfoldersAndFiles'
                Confirm           = $false
            }
            Add-NTFSAccessRule @denyParameters

            Test-IcaclsVerify -Path $path | Should -BeTrue
            Test-IcaclsVerify -Path $child | Should -BeTrue
        }

        It 'Should restore a tree to the descriptor icacls saved before the change' {
            $root = New-OracleDirectory -Name 'roundtrip'
            $child = Join-Path -Path $root -ChildPath 'child'
            $null = New-Item -Path $child -ItemType Directory -Force
            Set-Content -LiteralPath (Join-Path $child 'leaf.txt') -Value 'oracle'
            $addParameters = @{
                LiteralPath  = $root
                Account      = $script:inertSid
                AccessRights = 'ReadAndExecute'
                AppliesTo    = 'ThisFolderSubfoldersAndFiles'
                Confirm      = $false
            }
            Add-NTFSAccessRule @addParameters

            $targets = @($root) + @(
                Get-ChildItem -LiteralPath $root -Recurse -Force | ForEach-Object { $_.FullName }
            )
            $backupPath = Join-Path -Path $TestDrive -ChildPath 'roundtrip.json'
            $savedBefore = Join-Path -Path $TestDrive -ChildPath 'roundtrip-before.acl'
            $savedAfter = Join-Path -Path $TestDrive -ChildPath 'roundtrip-after.acl'

            $null = & icacls.exe $root /save $savedBefore /t /c /q
            Backup-NTFSItemSecurityDescriptor -LiteralPath $targets -DestinationPath $backupPath -Force

            Add-NTFSAccessRule -LiteralPath $child -Account 'S-1-5-11' -AccessRights 'FullControl' -Confirm:$false
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false

            $null = & icacls.exe $root /save $savedAfter /t /c /q

            $beforeBytes = [System.IO.File]::ReadAllBytes($savedBefore)
            $afterBytes = [System.IO.File]::ReadAllBytes($savedAfter)
            $afterBytes.Length | Should -Be $beforeBytes.Length
            [System.Convert]::ToBase64String($afterBytes) |
                Should -Be ([System.Convert]::ToBase64String($beforeBytes))
        }
    }
}
