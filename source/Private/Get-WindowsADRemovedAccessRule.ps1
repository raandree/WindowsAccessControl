function Get-WindowsADRemovedAccessRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [byte[]]$OriginalSecurityDescriptor,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    $removedAce = @(
        Get-WindowsADRemovedAce `
            -OriginalSecurityDescriptor $OriginalSecurityDescriptor `
            -SecurityDescriptor $SecurityDescriptor
    )
    foreach ($ace in $removedAce) {
        ConvertTo-WindowsADAccessRuleObject -Ace $ace -Target $Target
    }
}
