function Disable-NTFSItemInheritance {
    <#
    .SYNOPSIS
        Disables NTFS inheritance for files and directories.

    .DESCRIPTION
        Protects the selected access or audit ACL from parent changes. Existing
        inherited rules are converted to explicit rules by default so access is
        preserved; pass PreserveInherited false to discard them.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor with the selected sections loaded. When
        supplied, inheritance is disabled on the descriptor in memory and the
        descriptor is returned; nothing is written until
        Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both. Changing audit
        inheritance can require SeSecurityPrivilege.

    .PARAMETER PreserveInherited
        When true, converts inherited rules to explicit rules before blocking
        inheritance. Set this parameter to false to remove inherited rules.

    .PARAMETER PassThru
        Returns the updated inheritance state for each changed item.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Disable-NTFSItemInheritance -LiteralPath C:\Data -PreserveInherited $true

        Disables DACL inheritance while preserving the current effective rules.

    .INPUTS
        System.String
        System.IO.FileSystemInfo
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.Inheritance
        WindowsAccessControl.SecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.SecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,

        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',

        [Parameter()]
        [bool]$PreserveInherited = $true,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $security = Assert-NTFSDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections (ConvertTo-NTFSInheritanceSection -Section $Section)
            if ($Section -in @('Access', 'All')) {
                $security.SetAccessRuleProtection($true, $PreserveInherited)
            }
            if ($Section -in @('Audit', 'All')) {
                $security.SetAuditRuleProtection($true, $PreserveInherited)
            }
            Update-NTFSSecurityDescriptorObject -Descriptor $SecurityDescriptor
            $SecurityDescriptor
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $action = "Disable $Section rule inheritance; preserve inherited rules: $PreserveInherited"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $descriptorSections = ConvertTo-NTFSInheritanceSection -Section $Section
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $descriptorSections
                if ($Section -in @('Access', 'All')) {
                    $security.SetAccessRuleProtection($true, $PreserveInherited)
                }
                if ($Section -in @('Audit', 'All')) {
                    $security.SetAuditRuleProtection($true, $PreserveInherited)
                }
                $persistenceParameters = @{
                    Item              = $item
                    Security          = $security
                    ProtectionSection = $Section
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters

                if ($PassThru) {
                    ConvertTo-NTFSInheritanceObject -Security $security -Path $item.FullName -Section $Section
                }
            }
        }
    }
}
