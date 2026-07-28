function Close-WindowsTaskSchedulerComObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    if ([Runtime.InteropServices.Marshal]::IsComObject($InputObject)) {
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($InputObject)
    }
}