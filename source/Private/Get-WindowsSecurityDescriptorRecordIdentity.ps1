function Get-WindowsSecurityDescriptorRecordIdentity {
    <#
        .SYNOPSIS
            Returns the deduplication key for one backup record.

        .DESCRIPTION
            A directory object's canonical target embeds the domain controller
            that served it, so the same object captured through two controllers
            would produce two canonical targets and silently restore twice. Key
            a directory record on its domain partition plus immutable object
            GUID instead. Every other family keeps its canonical target.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Record
    )

    if ([string]$Record.ObjectFamily -eq 'ADObject') {
        return 'ADObject:{0}:{1}' -f
            ([string]$Record.DomainNamingContext).ToUpperInvariant(),
            ([guid]$Record.ObjectGuid).ToString('D').ToUpperInvariant()
    }
    [string]$Record.CanonicalTarget
}
