function Set-WindowsNtfsDscSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The DSC engine controls invocation before this private persistence boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl
    )

    if ([int]$Sections -le 0 -or [int]$Sections -gt 15) {
        throw [System.ArgumentOutOfRangeException]::new('Sections')
    }
    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
    $requestedDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $Sddl
    )
    if (($Sections -band [WindowsSecurityDescriptorSection]::Owner) -ne 0 -and
        -not $requestedDescriptor.Owner) {
        throw 'The supplied SDDL does not contain the selected owner.'
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Group) -ne 0 -and
        -not $requestedDescriptor.Group) {
        throw 'The supplied SDDL does not contain the selected primary group.'
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Access) -ne 0 -and
        -not $requestedDescriptor.DiscretionaryAcl) {
        throw 'The supplied SDDL does not contain a selected non-null DACL.'
    }
    $systemAclPresent = ([int]$requestedDescriptor.ControlFlags -band
        [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
        -not $systemAclPresent) {
        throw 'The supplied SDDL does not explicitly represent the selected SACL.'
    }

    $items = @(Resolve-NTFSPath -LiteralPath $Path)
    if ($items.Count -ne 1) {
        throw "DSC target '$Path' does not resolve to one filesystem item."
    }
    $item = $items[0]
    $security = Get-NTFSSecurityDescriptorForItem `
        -Item $item `
        -Sections $managedSections
    $currentDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $security.GetSecurityDescriptorBinaryForm(),
        0
    )
    $currentComparable = Get-WindowsAccessControlDscComparableSddl `
        -SecurityDescriptor $currentDescriptor `
        -Sections $Sections
    $requestedComparable = Get-WindowsAccessControlDscComparableSddl `
        -SecurityDescriptor $requestedDescriptor `
        -Sections $Sections
    if ($currentComparable -ceq $requestedComparable) {
        return
    }

    $security.SetSecurityDescriptorSddlForm($Sddl, $managedSections)
    $persistenceParameters = @{
        Item     = $item
        Security = $security
        Sections = $managedSections
    }
    $accessSelected = (
        $Sections -band [WindowsSecurityDescriptorSection]::Access
    ) -ne 0
    $auditSelected = (
        $Sections -band [WindowsSecurityDescriptorSection]::Audit
    ) -ne 0
    $auditProtectionSelected = $auditSelected -and
        $null -ne $requestedDescriptor.SystemAcl
    if ($accessSelected -and $auditProtectionSelected) {
        $persistenceParameters.ProtectionSection = 'All'
    } elseif ($accessSelected) {
        $persistenceParameters.ProtectionSection = 'Access'
    } elseif ($auditProtectionSelected) {
        $persistenceParameters.ProtectionSection = 'Audit'
    }
    Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
}
