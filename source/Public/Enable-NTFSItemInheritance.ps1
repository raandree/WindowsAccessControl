function Enable-NTFSItemInheritance {
    <#
    .SYNOPSIS
        Enables NTFS inheritance for files and directories.

    .DESCRIPTION
        Removes protection from the selected access or audit ACL so that the
        item can inherit rules from its parent directory.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both. Changing audit
        inheritance can require SeSecurityPrivilege.

    .PARAMETER RemoveExplicitRules
        Removes explicit rules from each selected ACL before inheritance is
        enabled. Inherited rules from the parent are unaffected.

    .PARAMETER PassThru
        Returns the updated inheritance state for each changed item.

    .EXAMPLE
        Get-ChildItem -LiteralPath C:\Data | Enable-NTFSItemInheritance

        Enables access-rule inheritance for each child item in C:\Data.

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
        [switch]$RemoveExplicitRules,

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
            if ($PSCmdlet.ShouldProcess($item.FullName, "Enable $Section rule inheritance")) {
                $descriptorSections = switch ($Section) {
                    'Access' { [System.Security.AccessControl.AccessControlSections]::Access }
                    'Audit' { [System.Security.AccessControl.AccessControlSections]::Audit }
                    'All' {
                        [System.Security.AccessControl.AccessControlSections]::Access -bor
                            [System.Security.AccessControl.AccessControlSections]::Audit
                    }
                }
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $descriptorSections
                if ($Section -in @('Access', 'All')) {
                    $security.SetAccessRuleProtection($false, $false)
                    if ($RemoveExplicitRules) {
                        $explicitAccessRules = $security.GetAccessRules(
                            $true,
                            $false,
                            [System.Security.Principal.SecurityIdentifier]
                        )
                        foreach ($explicitAccessRule in $explicitAccessRules) {
                            $security.RemoveAccessRuleSpecific($explicitAccessRule)
                        }
                    }
                }
                if ($Section -in @('Audit', 'All')) {
                    $security.SetAuditRuleProtection($false, $false)
                    if ($RemoveExplicitRules) {
                        $explicitAuditRules = $security.GetAuditRules(
                            $true,
                            $false,
                            [System.Security.Principal.SecurityIdentifier]
                        )
                        foreach ($explicitAuditRule in $explicitAuditRules) {
                            $security.RemoveAuditRuleSpecific($explicitAuditRule)
                        }
                    }
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
