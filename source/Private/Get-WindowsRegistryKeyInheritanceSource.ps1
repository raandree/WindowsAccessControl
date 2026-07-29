function Get-WindowsRegistryKeyInheritanceSource {
    <#
        .SYNOPSIS
            Resolves the ancestor key of every DACL ACE on a registry key.

        .DESCRIPTION
            Returns one entry per DACL ACE, in ACL order, so callers can align
            results by ACE index. An entry is empty when Windows reports no
            inheritance source. An empty result means Windows cannot report
            inheritance sources for the target at all.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    # GetInheritanceSource rejects the WOW64 registry-view object types.
    if ([int]$Target.NativeObjectType -ne [int][WindowsSecurityObjectType]::RegistryKey) {
        return , [string[]]@()
    }

    Initialize-WindowsAccessControlNativeType
    $sources = [WindowsAccessControl.NativeMethods]::GetRegistryKeyAccessRuleInheritanceSources(
        $Target.NativePath,
        [uint32][int]$Target.NativeObjectType,
        $SecurityDescriptor
    )

    , [string[]]@(
        foreach ($source in $sources) {
            ConvertFrom-WindowsRegistryNativePath $source.AncestorName
        }
    )
}
