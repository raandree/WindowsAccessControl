function Invoke-WindowsProcessAclRuleMutation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,
        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,
        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Set', 'Remove', 'Clear')]
        [string]$Operation,
        [Parameter()]
        [System.Security.Principal.SecurityIdentifier[]]$SecurityIdentifier,
        [Parameter()]
        [int]$AccessMask,
        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
        [Parameter()]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::None,
        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $sections = if ($RuleType -eq 'Audit') {
        [WindowsSecurityDescriptorSection]::Audit
    } else {
        [WindowsSecurityDescriptorSection]::Access
    }
    $mutate = {
        param(
            $operationTarget,
            $selectedRuleType,
            $selectedOperation,
            $identities,
            $mask,
            $qualifier,
            $selectedAuditFlags,
            $exactAce,
            $selectedSections
        )

        $currentDescriptor = [WindowsAccessControl.NativeMethods]::GetHandleSecurityDescriptor(
            [IntPtr]$operationTarget.Handle,
            [uint32][int][WindowsSecurityObjectType]::Kernel,
            [uint32][int]$selectedSections
        )
        $descriptor = $currentDescriptor
        $aceFlagMask = 0
        if (([int]$selectedAuditFlags -band
            [int][System.Security.AccessControl.AuditFlags]::Success) -ne 0) {
            $aceFlagMask = $aceFlagMask -bor
                [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess
        }
        if (([int]$selectedAuditFlags -band
            [int][System.Security.AccessControl.AuditFlags]::Failure) -ne 0) {
            $aceFlagMask = $aceFlagMask -bor
                [int][System.Security.AccessControl.AceFlags]::FailedAccess
        }

        if ($selectedOperation -in @('Add', 'Set')) {
            foreach ($sid in $identities) {
                $mutationParameters = @{
                    SecurityDescriptor = $descriptor
                    RuleType          = $selectedRuleType
                    Operation         = $selectedOperation
                    SecurityIdentifier = $sid
                    AccessMask        = $mask
                    AccessControlType = $qualifier
                    AceFlags          = [System.Security.AccessControl.AceFlags]$aceFlagMask
                }
                $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
            }
        } elseif ($selectedOperation -eq 'Remove') {
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = $selectedRuleType
                Operation         = 'Remove'
                NativeAce         = $exactAce
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
        } elseif ($identities.Count -eq 0) {
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = $selectedRuleType
                Operation         = 'Clear'
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
        } else {
            foreach ($sid in $identities) {
                $mutationParameters = @{
                    SecurityDescriptor = $descriptor
                    RuleType          = $selectedRuleType
                    Operation         = 'Clear'
                    SecurityIdentifier = $sid
                }
                $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
            }
        }

        $managedSections = ConvertTo-WindowsAccessControlSection -Sections $selectedSections
        $current = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $currentDescriptor,
            0
        )
        $requested = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $descriptor,
            0
        )
        if ($current.GetSddlForm($managedSections) -cne
            $requested.GetSddlForm($managedSections)) {
            [WindowsAccessControl.NativeMethods]::SetHandleSecurityDescriptor(
                [IntPtr]$operationTarget.Handle,
                [uint32][int][WindowsSecurityObjectType]::Kernel,
                [uint32][int]$selectedSections,
                $descriptor
            )
        }
    }
    $arguments = [System.Collections.Generic.List[object]]::new()
    $arguments.Add($RuleType)
    $arguments.Add($Operation)
    $arguments.Add($SecurityIdentifier)
    $arguments.Add($AccessMask)
    $arguments.Add($AccessControlType)
    $arguments.Add($AuditFlags)
    $arguments.Add($NativeAce)
    $arguments.Add($sections)
    $parameters = @{
        Target       = $Target
        Sections     = $sections
        Write        = $true
        ScriptBlock  = $mutate
        ArgumentList = $arguments.ToArray()
    }
    Invoke-WithWindowsProcessTarget @parameters
}
