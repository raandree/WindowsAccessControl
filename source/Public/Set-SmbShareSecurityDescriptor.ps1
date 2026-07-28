function Set-SmbShareSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets the DACL security descriptor on local SMB shares.
    .DESCRIPTION
        Parses SDDL as data, rejects null DACLs, and persists only the access
        section to ordinary local SMB shares while preserving other sections.
    .PARAMETER Name
        One or more unqualified local SMB share names.
    .PARAMETER Sddl
        A structurally valid SDDL document containing a non-null DACL.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical share targets from 1 through 64.
    .PARAMETER PassThru
        Returns the stored share DACL descriptor after persistence.
    .EXAMPLE
        Set-SmbShareSecurityDescriptor -Name 'Data$' -Sddl 'D:(A;;FA;;;BA)' -WhatIf

        Previews replacing only the share DACL.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.SmbShareSecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ShareName')]
        [object[]]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if (-not $rawDescriptor.DiscretionaryAcl) {
            throw 'The supplied SDDL does not contain a non-null DACL.'
        }
        $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsSmbShareCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Set SMB share DACL')) {
                $currentDescriptor = Get-WindowsNamedSecurityDescriptor `
                    -NativePath $target.NativePath `
                    -NativeObjectType $target.NativeObjectType `
                    -Sections Access
                Set-WindowsSmbShareSecurityDescriptor `
                    -Target $target `
                    -SecurityDescriptor $descriptorBytes `
                    -CurrentSecurityDescriptor $currentDescriptor
                if ($PassThru) {
                    Get-SmbShareSecurityDescriptor -Name $target.ShareName -ThrottleLimit 1
                }
            }
        }
    }
}
