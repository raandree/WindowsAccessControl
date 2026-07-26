function Get-WindowsProcessTargetSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    $readDescriptor = {
        param($operationTarget, $selectedSections)

        [WindowsAccessControl.NativeMethods]::GetHandleSecurityDescriptor(
            [IntPtr]$operationTarget.Handle,
            [uint32][int][WindowsSecurityObjectType]::Kernel,
            [uint32][int]$selectedSections
        )
    }
    $parameters = @{
        Target      = $Target
        Sections    = $Sections
        ScriptBlock = $readDescriptor
        ArgumentList = @($Sections)
    }
    Invoke-WithWindowsProcessTarget @parameters
}
