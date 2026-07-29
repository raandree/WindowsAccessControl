function Edit-RegistryKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Edits selected registry key descriptor sections in one bounded scope.
    .DESCRIPTION
        Reads one detached security descriptor per canonical registry target,
        invokes a caller script block with that descriptor and optional
        arguments, then persists the originally selected sections at most once.
        Callback output is suppressed; use PassThru for the edited descriptor. A
        callback error or unloaded-section expansion prevents persistence.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Sections
        Selects the descriptor sections loaded and eligible for persistence.
    .PARAMETER ScriptBlock
        Receives the detached descriptor as its first positional argument.
        Mutations made through descriptor-aware commands remain in memory until
        this scope persists them.
    .PARAMETER ArgumentList
        Supplies additional positional arguments after the descriptor.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER RequireUnchanged
        Rejects the write when the selected sections changed between this
        scope's read and its persist step. The default is last-writer-wins.
    .PARAMETER ThrottleLimit
        Accepted for target-array command consistency. Caller script blocks are
        intentionally dispatched sequentially to preserve runspace affinity;
        values greater than one do not parallelize this command.
    .PARAMETER PassThru
        Returns the edited descriptor after persistence without rereading it.
    .EXAMPLE
        Edit-RegistryKeySecurityDescriptor -Path HKCU:\Software -Sections Access {
            param($descriptor)
            $descriptor | Add-RegistryKeyAccessRule `
                -Account 'CONTOSO\Analysts' `
                -AccessRights ReadKey | Out-Null
        }

        Reads and writes the Software key DACL once while staging the rule.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,

        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::Access,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter()]
        [switch]$RequireUnchanged,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit 1 `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }

        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $readParameters = @{
                NativePath       = $target.NativePath
                NativeObjectType = $target.NativeObjectType
                Sections         = $Sections
            }
            $currentBytes = Get-WindowsNamedSecurityDescriptor @readParameters
            $descriptor = ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections $Sections `
                -SecurityDescriptor $currentBytes `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'

            $null = & $ScriptBlock $descriptor @ArgumentList

            if ('WindowsAccessControl.RegistryKeySecurityDescriptor' -notin
                $descriptor.PSObject.TypeNames -or
                -not $descriptor.BinarySecurityDescriptor) {
                throw [InvalidOperationException]::new(
                    'The edit callback must retain the supplied WindowsAccessControl.RegistryKeySecurityDescriptor and its binary descriptor.'
                )
            }
            $unloadedSections = [int]$descriptor.Sections -band (-bnot [int]$Sections)
            if ($unloadedSections -ne 0) {
                throw [InvalidOperationException]::new(
                    'The edit callback selected descriptor sections that were not loaded.'
                )
            }
            $descriptor.Sections = $Sections

            $action = "Persist edited $Sections registry security descriptor sections"
            if ($PSCmdlet.ShouldProcess($target.Path, $action)) {
                if ($RequireUnchanged) {
                    $verifyBytes = Get-WindowsNamedSecurityDescriptor @readParameters
                    $verified = ConvertTo-WindowsSecurityDescriptorObject `
                        -Target $target `
                        -Sections $Sections `
                        -SecurityDescriptor $verifyBytes `
                        -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken $descriptor.ConcurrencyToken `
                        -CurrentToken $verified.ConcurrencyToken `
                        -Target $target.Path
                }
                $writeParameters = @{
                    NativePath                = $target.NativePath
                    NativeObjectType          = $target.NativeObjectType
                    Sections                  = $Sections
                    SecurityDescriptor        = [byte[]]$descriptor.BinarySecurityDescriptor
                    CurrentSecurityDescriptor = $currentBytes
                }
                Set-WindowsNamedSecurityDescriptor @writeParameters

                if ($PassThru) {
                    ConvertTo-WindowsSecurityDescriptorObject `
                        -Target $target `
                        -Sections $Sections `
                        -SecurityDescriptor ([byte[]]$descriptor.BinarySecurityDescriptor) `
                        -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
                }
            }
        }
    }
}
