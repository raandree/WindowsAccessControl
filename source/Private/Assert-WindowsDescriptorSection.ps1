function Assert-WindowsDescriptorSection {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [psobject]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$RequiredSections,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    if ($TypeName -notin $SecurityDescriptor.PSObject.TypeNames -or
        -not $SecurityDescriptor.BinarySecurityDescriptor) {
        throw [InvalidOperationException]::new(
            "The descriptor must be a $TypeName object returned by its Get-*SecurityDescriptor command."
        )
    }

    # Editing an unloaded section would persist an empty ACL over the live one.
    $missingSections = [int]$RequiredSections -band (-bnot [int]$SecurityDescriptor.Sections)
    if ($missingSections -ne 0) {
        $missingName = [WindowsSecurityDescriptorSection]$missingSections
        throw [InvalidOperationException]::new(
            "The descriptor was read without the $missingName section, so that section cannot be edited."
        )
    }

    , [byte[]]$SecurityDescriptor.BinarySecurityDescriptor
}
