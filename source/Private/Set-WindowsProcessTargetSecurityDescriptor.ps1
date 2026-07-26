function Set-WindowsProcessTargetSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public process commands enforce ShouldProcess before this boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    $setDescriptor = {
        param($operationTarget, $descriptorBytes, $selectedSections)

        $currentBytes = [WindowsAccessControl.NativeMethods]::GetHandleSecurityDescriptor(
            [IntPtr]$operationTarget.Handle,
            [uint32][int][WindowsSecurityObjectType]::Kernel,
            [uint32][int]$selectedSections
        )
        $managedSections = ConvertTo-WindowsAccessControlSection -Sections $selectedSections
        $current = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $currentBytes,
            0
        )
        $requested = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $descriptorBytes,
            0
        )
        if ($current.GetSddlForm($managedSections) -ceq
            $requested.GetSddlForm($managedSections)) {
            return
        }
        [WindowsAccessControl.NativeMethods]::SetHandleSecurityDescriptor(
            [IntPtr]$operationTarget.Handle,
            [uint32][int][WindowsSecurityObjectType]::Kernel,
            [uint32][int]$selectedSections,
            $descriptorBytes
        )
    }
    $arguments = [System.Collections.Generic.List[object]]::new()
    $arguments.Add($SecurityDescriptor)
    $arguments.Add($Sections)
    $parameters = @{
        Target       = $Target
        Sections     = $Sections
        Write        = $true
        ScriptBlock  = $setDescriptor
        ArgumentList = $arguments.ToArray()
    }
    Invoke-WithWindowsProcessTarget @parameters
}
