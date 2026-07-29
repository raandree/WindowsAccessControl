function Set-RegistryKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Sets selected security descriptor sections on local registry keys.
    .DESCRIPTION
        Parses SDDL as data and persists only the selected owner, group, DACL,
        or SACL sections to local registry keys while honoring PowerShell
        confirmation and preview semantics.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey objects supplied
        directly or through the pipeline.
    .PARAMETER Sddl
        A structurally valid SDDL document containing every selected section.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor, optionally after in-memory edits. Its
        recorded target, registry view, and selected sections are used.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER Sections
        Selects the descriptor sections to persist from the SDDL document.
    .PARAMETER RequireUnchanged
        Rejects the write when the selected sections of the live key no longer
        match the ConcurrencyToken recorded when the descriptor was read. The
        default is last-writer-wins.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns the updated selected descriptor sections after persistence.
    .EXAMPLE
        Set-RegistryKeySecurityDescriptor -Path HKCU:\Software -Sddl 'D:(A;;KR;;;WD)' -Sections Access -WhatIf

        Previews replacing only the Software key DACL.
    .EXAMPLE
        Get-RegistryKeySecurityDescriptor -Path HKCU:\Software -Sections Access |
            Add-RegistryKeyAccessRule -Account Everyone -AccessRights ReadKey |
            Set-RegistryKeySecurityDescriptor

        Stages a read rule in memory and persists the DACL with one write.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
        WindowsAccessControl.RegistryKeySecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'SecurityDescriptor')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Sddl')]
        [Alias('PSPath')]
        [object[]]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Sddl')]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.RegistryKeySecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,

        [Parameter(ParameterSetName = 'Sddl')]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter(ParameterSetName = 'Sddl')]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All,

        [Parameter(ParameterSetName = 'SecurityDescriptor')]
        [switch]$RequireUnchanged,

        [Parameter(ParameterSetName = 'Sddl')]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        if ($PSBoundParameters.ContainsKey('Sddl')) {
            $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
            if (($Sections -band [WindowsSecurityDescriptorSection]::Access) -ne 0 -and
                -not $rawDescriptor.DiscretionaryAcl) {
                throw 'The supplied SDDL does not contain a non-null DACL.'
            }
            $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
                [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
            if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
                -not $systemAclPresent) {
                throw 'The supplied SDDL does not contain a SACL.'
            }
            $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
            $requestedSddl = $rawDescriptor.GetSddlForm($managedSections)
            $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
            $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $descriptorSections = [WindowsSecurityDescriptorSection]$SecurityDescriptor.Sections
            $descriptorView = [WindowsRegistryView]$SecurityDescriptor.RegistryView
            $descriptorTarget = Resolve-RegistryKeyTarget `
                -Path $SecurityDescriptor.Path `
                -RegistryView $descriptorView
            $action = "Persist $descriptorSections registry security"
            if ($PSCmdlet.ShouldProcess($descriptorTarget.Path, $action)) {
                $readParameters = @{
                    NativePath       = $descriptorTarget.NativePath
                    NativeObjectType = $descriptorTarget.NativeObjectType
                    Sections         = $descriptorSections
                }
                $currentBytes = Get-WindowsNamedSecurityDescriptor @readParameters
                if ($RequireUnchanged) {
                    $currentDescriptorObject = ConvertTo-WindowsSecurityDescriptorObject `
                        -Target $descriptorTarget `
                        -Sections $descriptorSections `
                        -SecurityDescriptor $currentBytes `
                        -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken $SecurityDescriptor.ConcurrencyToken `
                        -CurrentToken $currentDescriptorObject.ConcurrencyToken `
                        -Target $descriptorTarget.Path
                }
                $writeParameters = @{
                    NativePath                = $descriptorTarget.NativePath
                    NativeObjectType          = $descriptorTarget.NativeObjectType
                    Sections                  = $descriptorSections
                    SecurityDescriptor        = [byte[]]$SecurityDescriptor.BinarySecurityDescriptor
                    CurrentSecurityDescriptor = $currentBytes
                }
                Set-WindowsNamedSecurityDescriptor @writeParameters
                if ($PassThru) {
                    Update-WindowsSecurityDescriptorObject `
                        -Descriptor $SecurityDescriptor `
                        -SecurityDescriptor ([byte[]]$SecurityDescriptor.BinarySecurityDescriptor) `
                        -RefreshConcurrencyToken
                    $SecurityDescriptor
                }
            }
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, "Set $Sections registry security")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = $Sections
                }
                $currentBytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $currentDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                    $currentBytes,
                    0
                )
                if ($currentDescriptor.GetSddlForm($managedSections) -cne $requestedSddl) {
                    $setParameters = @{
                        NativePath         = $target.NativePath
                        NativeObjectType   = $target.NativeObjectType
                        Sections           = $Sections
                        SecurityDescriptor = $descriptorBytes
                        CurrentSecurityDescriptor = $currentBytes
                    }
                    Set-WindowsNamedSecurityDescriptor @setParameters
                }
                if ($PassThru) {
                    $getResultParameters = @{
                        Path         = $target.Path
                        RegistryView = $RegistryView
                        Sections     = $Sections
                    }
                    Get-RegistryKeySecurityDescriptor @getResultParameters
                }
            }
        }
    }
}
