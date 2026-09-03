. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Remove-TaskFolderAccessRule' `
    -RequiredParameters @('InputObject', 'AllowedRootPath', 'PassThru') `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false

Describe 'Remove-TaskFolderAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    }

    It 'Should reject an inherited rule and an untyped input object' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsTaskSchedulerAclRuleMutation

            $ace = [Security.AccessControl.CommonAce]::new(
                [Security.AccessControl.AceFlags]::Inherited,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                0x00120089,
                [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null)
            $inheritedRule = [pscustomobject]@{
                TaskPath        = '\Operations'
                CanonicalTarget = 'TaskFolder:WACHOST:\OPERATIONS'
                SID             = 'S-1-1-0'
                IsInherited     = $true
                NativeAce       = $ace
            }
            $inheritedRule.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.TaskFolderAccessRule')

            {
                $inheritedRule | Remove-TaskFolderAccessRule `
                    -AllowedRootPath '\Operations' -Confirm:$false
            } | Should -Throw -ExpectedMessage '*inherited task-folder rule*'

            {
                [pscustomobject]@{ TaskPath = '\Operations' } |
                    Remove-TaskFolderAccessRule -AllowedRootPath '\Operations' -Confirm:$false
            } | Should -Throw -ExpectedMessage '*Get-TaskFolderAccessRule*'

            Should -Invoke Invoke-WindowsTaskSchedulerAclRuleMutation -Times 0 -Exactly
        }
    }

    It 'Should remove exactly one native ACE from the revalidated target' {
        InModuleScope WindowsAccessControl {
            $script:target = [pscustomobject]@{
                ObjectType       = 'TaskFolder'
                Path             = '\Operations'
                TaskPath         = '\Operations'
                CanonicalTarget  = 'TaskFolder:WACHOST:\OPERATIONS'
                DescriptorSource = 'TaskSchedulerCom'
            }
            Mock Resolve-WindowsTaskSchedulerTarget { $script:target }
            Mock Invoke-WindowsTaskSchedulerAclRuleMutation

            $ace = [Security.AccessControl.CommonAce]::new(
                [Security.AccessControl.AceFlags]::None,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                0x00120089,
                [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null)
            $rule = [pscustomobject]@{
                TaskPath        = '\Operations'
                CanonicalTarget = 'TaskFolder:WACHOST:\OPERATIONS'
                SID             = 'S-1-1-0'
                IsInherited     = $false
                NativeAce       = $ace
            }
            $rule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.TaskFolderAccessRule')

            $passThru = $rule | Remove-TaskFolderAccessRule `
                -AllowedRootPath '\Operations' -PassThru -Confirm:$false

            $passThru.SID | Should -BeExactly 'S-1-1-0'
            Should -Invoke Invoke-WindowsTaskSchedulerAclRuleMutation `
                -Times 1 -Exactly -ParameterFilter {
                    $Operation -eq 'Remove' -and $NativeAce -eq $ace
                }
            Should -Invoke Resolve-WindowsTaskSchedulerTarget -Times 1 -Exactly `
                -ParameterFilter { $ForWrite -and $AllowedRootPath -eq '\Operations' }
        }
    }
}
