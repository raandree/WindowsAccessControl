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

    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both. Changing audit
        inheritance can require SeSecurityPrivilege.

    .PARAMETER PreserveInherited
        When true, converts inherited rules to explicit rules before blocking
        inheritance. Set this parameter to false to remove inherited rules.

    .PARAMETER PassThru
        Returns the updated inheritance state for each changed item.

    .EXAMPLE
        Disable-NTFSItemInheritance -LiteralPath C:\Data -PreserveInherited $true

        Disables DACL inheritance while preserving the current effective rules.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        WindowsAccessControl.Inheritance
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

        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',

        [Parameter()]
        [bool]$PreserveInherited = $true,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $action = "Disable $Section rule inheritance; preserve inherited rules: $PreserveInherited"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $getAclParameters = @{
                    LiteralPath = $item.FullName
                    ErrorAction = 'Stop'
                }
                if ($Section -in @('Audit', 'All')) {
                    $getAclParameters.Audit = $true
                }
                $security = Get-Acl @getAclParameters
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