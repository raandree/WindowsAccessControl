function Set-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Persists an edited NTFS security descriptor object to its item.

    .DESCRIPTION
        Writes the selected sections of a WindowsAccessControl.SecurityDescriptor
        object back to the filesystem item it was read from. The descriptor is
        obtained from Get-NTFSItemSecurityDescriptor and can be edited in memory
        by piping it through mutating commands such as Add-NTFSAccessRule before
        it is persisted. Only the sections recorded on the descriptor are
        written, and the write happens once under ShouldProcess.

    .PARAMETER InputObject
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor, optionally after in-memory edits.

    .PARAMETER PassThru
        Returns the descriptor object after it is persisted. By default, the
        command does not emit output.

    .EXAMPLE
        Get-NTFSItemSecurityDescriptor -LiteralPath C:\Data -Sections Access |
            Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read |
            Set-NTFSItemSecurityDescriptor

        Stages a read access rule in memory and persists the DACL with one write.

    .INPUTS
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.SecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject]$InputObject,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ('WindowsAccessControl.SecurityDescriptor' -notin $InputObject.PSObject.TypeNames) {
            throw 'InputObject must be a WindowsAccessControl.SecurityDescriptor returned by Get-NTFSItemSecurityDescriptor.'
        }

        $items = @(Resolve-NTFSPath -LiteralPath $InputObject.Path)
        if ($items.Count -ne 1) {
            throw "The descriptor path '$($InputObject.Path)' must resolve to exactly one filesystem item."
        }
        $item = $items[0]
        $sections = [System.Security.AccessControl.AccessControlSections]$InputObject.Sections

        $action = "Persist $sections security descriptor sections"
        if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
            $persistenceParameters = @{
                Item     = $item
                Security = [System.Security.AccessControl.FileSystemSecurity]$InputObject.NativeSecurity
                Sections = $sections
            }
            Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters

            if ($PassThru) {
                $InputObject
            }
        }
    }
}
