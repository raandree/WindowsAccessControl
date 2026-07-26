function Get-WindowsAccessControlDscComparableSddl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    $descriptorBytes = [byte[]]::new($SecurityDescriptor.BinaryLength)
    $SecurityDescriptor.GetBinaryForm($descriptorBytes, 0)
    $comparableDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $descriptorBytes,
        0
    )
    $autoInheritedFlags =
        [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited -bor
        [int][System.Security.AccessControl.ControlFlags]::SystemAclAutoInherited
    $comparableDescriptor.SetFlags(
        [System.Security.AccessControl.ControlFlags](
            [int]$comparableDescriptor.ControlFlags -band
                (-bnot $autoInheritedFlags)
        )
    )
    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
    $comparableDescriptor.GetSddlForm($managedSections)
}
