function Get-RegistryKeyAuditRule {
    <#
    .SYNOPSIS
        Gets audit rules from local registry keys.
    .DESCRIPTION
        Reads registry-key SACLs under a scoped security privilege and emits
        structured audit rules with account, SID, registry rights, audit flags,
        inheritance scope, and native ACE.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER Account
        Filters rules by account names, SID strings, or module identity output.
    .PARAMETER ExcludeInherited
        Excludes inherited rules and returns only explicit registry audit ACEs.
    .PARAMETER ExcludeExplicit
        Excludes explicit rules and returns only inherited registry audit ACEs.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .EXAMPLE
        Get-RegistryKeyAuditRule -Path HKCU:\Software -ExcludeInherited

        Gets explicit audit rules from the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        WindowsAccessControl.RegistryKeyAuditRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter()]
        [switch]$ExcludeInherited,

        [Parameter()]
        [switch]$ExcludeExplicit,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        )
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $parameters = @{
                Target           = $target
                RuleType         = 'Audit'
                Account          = $Account
                ExcludeInherited = $ExcludeInherited
                ExcludeExplicit  = $ExcludeExplicit
                TypeName         = 'WindowsAccessControl.RegistryKeyAuditRule'
            }
            Get-WindowsAclRule @parameters
        }
    }
}
