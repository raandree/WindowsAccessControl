function Get-SmbShareSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets the DACL security descriptor from local SMB shares.
    .DESCRIPTION
        Resolves unqualified ordinary local share names and returns their DACL
        as portable SDDL plus the exact binary and native descriptor forms.
    .PARAMETER Name
        One or more unqualified local SMB share names.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical share targets from 1 through 64.
    .EXAMPLE
        Get-SmbShareSecurityDescriptor -Name 'Data$'

        Gets the DACL descriptor for the local hidden Data share.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.SmbShareSecurityDescriptor
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ShareName')]
        [object[]]$Name,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsSmbShareCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            $descriptor = Get-WindowsNamedSecurityDescriptor `
                -NativePath $target.NativePath `
                -NativeObjectType $target.NativeObjectType `
                -Sections Access
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections Access `
                -SecurityDescriptor $descriptor `
                -TypeName 'WindowsAccessControl.SmbShareSecurityDescriptor'
        }
    }
}
