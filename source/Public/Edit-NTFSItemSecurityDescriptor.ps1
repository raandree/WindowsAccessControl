function Edit-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Edits selected NTFS descriptor sections in one bounded scope.
    .DESCRIPTION
        Reads one detached security descriptor per canonical target, invokes a
        caller script block with that descriptor and optional arguments, then
        persists the originally selected sections at most once. Callback output
        is suppressed; use PassThru for the edited descriptor. A callback error
        or unloaded-section expansion prevents persistence.
    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and strings can be supplied through the pipeline.
    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied.
    .PARAMETER Sections
        Selects the descriptor sections loaded and eligible for persistence.
    .PARAMETER ScriptBlock
        Receives the detached descriptor as its first positional argument.
        Mutations made through descriptor-aware commands remain in memory until
        this scope persists them.
    .PARAMETER ArgumentList
        Supplies additional positional arguments after the descriptor.
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
        Edit-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access {
            param($descriptor)
            $descriptor | Add-NTFSAccessRule `
                -Account 'CONTOSO\Analysts' `
                -AccessRights Read | Out-Null
        }

        Reads and writes the DACL once while staging the rule in memory.
    .INPUTS
        System.String
        System.IO.FileSystemInfo
    .OUTPUTS
        None
        WindowsAccessControl.SecurityDescriptor
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'Path'
    )]
    [OutputType([pscustomobject])]
    param(
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Path'
        )]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path = '.',

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'LiteralPath'
        )]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter()]
        [Security.AccessControl.AccessControlSections]$Sections =
            [Security.AccessControl.AccessControlSections]::Access,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [switch]$RequireUnchanged,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit 1 `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }

        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        }
        else {
            $resolveParameters.Path = $Path
        }
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $security = Get-NTFSSecurityDescriptorForItem `
                -Item $item `
                -Sections $Sections
            $descriptor = ConvertTo-NTFSSecurityDescriptorObject `
                -Item $item `
                -Security $security `
                -Sections $Sections

            $null = & $ScriptBlock $descriptor @ArgumentList

            if ('WindowsAccessControl.SecurityDescriptor' -notin
                $descriptor.PSObject.TypeNames -or
                $descriptor.NativeSecurity -isnot
                [Security.AccessControl.FileSystemSecurity]) {
                throw [InvalidOperationException]::new(
                    'The edit callback must retain the supplied WindowsAccessControl.SecurityDescriptor and its native filesystem descriptor.'
                )
            }
            $unloadedSections = [int]$descriptor.Sections -band
                (-bnot [int]$Sections)
            if ($unloadedSections -ne 0) {
                throw [InvalidOperationException]::new(
                    'The edit callback selected descriptor sections that were not loaded.'
                )
            }
            $descriptor.Sections = $Sections

            $protectionSection = $null
            $hasAccess = ([int]$Sections -band
                [int][Security.AccessControl.AccessControlSections]::Access) -ne 0
            $hasAudit = ([int]$Sections -band
                [int][Security.AccessControl.AccessControlSections]::Audit) -ne 0
            if ($hasAccess -and $hasAudit) {
                $protectionSection = 'All'
            }
            elseif ($hasAccess) {
                $protectionSection = 'Access'
            }
            elseif ($hasAudit) {
                $protectionSection = 'Audit'
            }

            $action = "Persist edited $Sections security descriptor sections"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                if ($RequireUnchanged) {
                    $currentSecurity = Get-NTFSSecurityDescriptorForItem `
                        -Item $item `
                        -Sections $Sections
                    $current = ConvertTo-NTFSSecurityDescriptorObject `
                        -Item $item `
                        -Security $currentSecurity `
                        -Sections $Sections
                    Assert-WindowsDescriptorUnchanged `
                        -ExpectedToken $descriptor.ConcurrencyToken `
                        -CurrentToken $current.ConcurrencyToken `
                        -Target $item.FullName
                }
                $persistenceParameters = @{
                    Item     = $item
                    Security = [Security.AccessControl.FileSystemSecurity](
                        $descriptor.NativeSecurity
                    )
                    Sections = $Sections
                }
                if ($protectionSection) {
                    $persistenceParameters.ProtectionSection = $protectionSection
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters

                if ($PassThru) {
                    ConvertTo-NTFSSecurityDescriptorObject `
                        -Item $item `
                        -Security $descriptor.NativeSecurity `
                        -Sections $Sections
                }
            }
        }
    }
}