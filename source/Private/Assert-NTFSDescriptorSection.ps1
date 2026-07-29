function Assert-NTFSDescriptorSection {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemSecurity])]
    param(
        [Parameter(Mandatory)]
        [psobject]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlSections]$RequiredSections
    )

    if ('WindowsAccessControl.SecurityDescriptor' -notin $SecurityDescriptor.PSObject.TypeNames -or
        $SecurityDescriptor.NativeSecurity -isnot [System.Security.AccessControl.FileSystemSecurity]) {
        throw [InvalidOperationException]::new(
            'The descriptor must be a WindowsAccessControl.SecurityDescriptor returned by Get-NTFSItemSecurityDescriptor.'
        )
    }

    # Editing an unloaded section would persist an empty ACL over the live one.
    $missingSections = [int]$RequiredSections -band (-bnot [int]$SecurityDescriptor.Sections)
    if ($missingSections -ne 0) {
        $missingName = [System.Security.AccessControl.AccessControlSections]$missingSections
        throw [InvalidOperationException]::new(
            "The descriptor was read without the $missingName section, so that section cannot be edited."
        )
    }

    [System.Security.AccessControl.FileSystemSecurity]$SecurityDescriptor.NativeSecurity
}
