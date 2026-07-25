function ConvertTo-WindowsRegistryAceFlag {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AceFlags])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ThisKeyOnly', 'ThisKeyAndSubkeys', 'SubkeysOnly',
            'ThisKeyAndSubkeysOneLevel', 'SubkeysOnlyOneLevel'
        )]
        [string]$AppliesTo,

        [Parameter()]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::None
    )

    $flagMask = switch ($AppliesTo) {
        ThisKeyOnly { [int][System.Security.AccessControl.AceFlags]::None }
        ThisKeyAndSubkeys {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit
        }
        SubkeysOnly {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::InheritOnly
        }
        ThisKeyAndSubkeysOneLevel {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
        }
        SubkeysOnlyOneLevel {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
                [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
        }
    }
    if (([int]$AuditFlags -band
        [int][System.Security.AccessControl.AuditFlags]::Success) -ne 0) {
        $flagMask = $flagMask -bor
            [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess
    }
    if (([int]$AuditFlags -band
        [int][System.Security.AccessControl.AuditFlags]::Failure) -ne 0) {
        $flagMask = $flagMask -bor
            [int][System.Security.AccessControl.AceFlags]::FailedAccess
    }
    [System.Security.AccessControl.AceFlags]$flagMask
}
