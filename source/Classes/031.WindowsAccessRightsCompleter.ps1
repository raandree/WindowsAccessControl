class WindowsAccessRightsCompletion {
    hidden [System.Collections.Generic.IEnumerable[System.Management.Automation.CompletionResult]] Complete(
        [type]$RightsType,
        [string]$WordToComplete
    ) {
        $results = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
        $word = if ($WordToComplete) { $WordToComplete.Trim("'", '"') } else { '' }
        $pattern = '{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($word)

        foreach ($name in [System.Enum]::GetNames($RightsType)) {
            if ($name -like $pattern) {
                $results.Add(
                    [System.Management.Automation.CompletionResult]::new(
                        $name,
                        $name,
                        [System.Management.Automation.CompletionResultType]::ParameterValue,
                        "$name ($($RightsType.Name))"
                    )
                )
            }
        }

        return $results
    }
}

class WindowsFileSystemRightsCompleter : WindowsAccessRightsCompletion, System.Management.Automation.IArgumentCompleter {
    [System.Collections.Generic.IEnumerable[System.Management.Automation.CompletionResult]] CompleteArgument(
        [string]$commandName,
        [string]$parameterName,
        [string]$wordToComplete,
        [System.Management.Automation.Language.CommandAst]$commandAst,
        [System.Collections.IDictionary]$fakeBoundParameters
    ) {
        return $this.Complete(
            [System.Security.AccessControl.FileSystemRights],
            $wordToComplete
        )
    }
}

class WindowsActiveDirectoryRightsCompleter : WindowsAccessRightsCompletion, System.Management.Automation.IArgumentCompleter {
    [System.Collections.Generic.IEnumerable[System.Management.Automation.CompletionResult]] CompleteArgument(
        [string]$commandName,
        [string]$parameterName,
        [string]$wordToComplete,
        [System.Management.Automation.Language.CommandAst]$commandAst,
        [System.Collections.IDictionary]$fakeBoundParameters
    ) {
        return $this.Complete(
            [WindowsActiveDirectoryRights],
            $wordToComplete
        )
    }
}
