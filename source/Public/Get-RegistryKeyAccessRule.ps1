function Get-RegistryKeyAccessRule {
    <#
    .SYNOPSIS
        Gets access rules from local registry keys.
    .DESCRIPTION
        Reads registry-key DACLs and emits structured allow or deny rules with
        account, SID, typed registry rights, inheritance scope, and native ACE.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER Account
        Filters rules by account names, SID strings, or module identity output.
    .PARAMETER ExcludeInherited
        Excludes inherited rules and returns only explicit registry ACEs.
    .PARAMETER ExcludeExplicit
        Excludes explicit rules and returns only inherited registry ACEs.
    .EXAMPLE
        Get-RegistryKeyAccessRule -Path HKCU:\Software -ExcludeInherited

        Gets explicit access rules from the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        WindowsAccessControl.RegistryKeyAccessRule
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
        [switch]$ExcludeExplicit
    )

    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $parameters = @{
                Target           = $target
                RuleType         = 'Access'
                Account          = $Account
                ExcludeInherited = $ExcludeInherited
                ExcludeExplicit  = $ExcludeExplicit
                TypeName         = 'WindowsAccessControl.RegistryKeyAccessRule'
            }
            Get-WindowsAclRule @parameters
        }
    }
}
