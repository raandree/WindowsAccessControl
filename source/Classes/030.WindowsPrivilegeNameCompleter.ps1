class WindowsPrivilegeNameCompleter : System.Management.Automation.IArgumentCompleter {
    # The privilege constants defined by winnt.h, mapped to the user right name
    # the Windows security policy editor shows for each one.
    static [System.Collections.Specialized.OrderedDictionary] GetKnownPrivilege() {
        return [ordered]@{
            SeAssignPrimaryTokenPrivilege             = 'Replace a process level token'
            SeAuditPrivilege                          = 'Generate security audits'
            SeBackupPrivilege                         = 'Back up files and directories'
            SeChangeNotifyPrivilege                   = 'Bypass traverse checking'
            SeCreateGlobalPrivilege                   = 'Create global objects'
            SeCreatePagefilePrivilege                 = 'Create a pagefile'
            SeCreatePermanentPrivilege                = 'Create permanent shared objects'
            SeCreateSymbolicLinkPrivilege             = 'Create symbolic links'
            SeCreateTokenPrivilege                    = 'Create a token object'
            SeDebugPrivilege                          = 'Debug programs'
            SeDelegateSessionUserImpersonatePrivilege = 'Obtain an impersonation token for another user in the same session'
            SeEnableDelegationPrivilege               = 'Enable computer and user accounts to be trusted for delegation'
            SeImpersonatePrivilege                    = 'Impersonate a client after authentication'
            SeIncreaseBasePriorityPrivilege           = 'Increase scheduling priority'
            SeIncreaseQuotaPrivilege                  = 'Adjust memory quotas for a process'
            SeIncreaseWorkingSetPrivilege             = 'Increase a process working set'
            SeLoadDriverPrivilege                     = 'Load and unload device drivers'
            SeLockMemoryPrivilege                     = 'Lock pages in memory'
            SeMachineAccountPrivilege                 = 'Add workstations to domain'
            SeManageVolumePrivilege                   = 'Perform volume maintenance tasks'
            SeProfileSingleProcessPrivilege           = 'Profile single process'
            SeRelabelPrivilege                        = 'Modify an object label'
            SeRemoteShutdownPrivilege                 = 'Force shutdown from a remote system'
            SeRestorePrivilege                        = 'Restore files and directories'
            SeSecurityPrivilege                       = 'Manage auditing and security log'
            SeShutdownPrivilege                       = 'Shut down the system'
            SeSyncAgentPrivilege                      = 'Synchronize directory service data'
            SeSystemEnvironmentPrivilege              = 'Modify firmware environment values'
            SeSystemProfilePrivilege                  = 'Profile system performance'
            SeSystemtimePrivilege                     = 'Change the system time'
            SeTakeOwnershipPrivilege                  = 'Take ownership of files or other objects'
            SeTcbPrivilege                            = 'Act as part of the operating system'
            SeTimeZonePrivilege                       = 'Change the time zone'
            SeTrustedCredManAccessPrivilege           = 'Access Credential Manager as a trusted caller'
            SeUndockPrivilege                         = 'Remove computer from docking station'
            SeUnsolicitedInputPrivilege               = 'Read unsolicited input from a terminal device'
        }
    }

    [System.Collections.Generic.IEnumerable[System.Management.Automation.CompletionResult]] CompleteArgument(
        [string]$commandName,
        [string]$parameterName,
        [string]$wordToComplete,
        [System.Management.Automation.Language.CommandAst]$commandAst,
        [System.Collections.IDictionary]$fakeBoundParameters
    ) {
        $results = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
        $word = if ($wordToComplete) { $wordToComplete.Trim("'", '"') } else { '' }
        # Every constant starts with the same two characters, so a fragment
        # anywhere in the name is matched instead of a prefix only. The typed
        # text is literal, so an unbalanced bracket cannot fail the keystroke.
        $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($word)

        foreach ($privilege in [WindowsPrivilegeNameCompleter]::GetKnownPrivilege().GetEnumerator()) {
            if ($privilege.Key -like $pattern) {
                $results.Add(
                    [System.Management.Automation.CompletionResult]::new(
                        $privilege.Key,
                        $privilege.Key,
                        [System.Management.Automation.CompletionResultType]::ParameterValue,
                        "$($privilege.Key): $($privilege.Value)"
                    )
                )
            }
        }

        return $results
    }
}
