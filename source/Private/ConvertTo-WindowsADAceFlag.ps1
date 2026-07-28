function ConvertTo-WindowsADAceFlag {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AceFlags])]
    param(
        [Parameter(Mandatory)]
        [WindowsActiveDirectoryInheritance]$InheritanceType
    )

    $flags = switch ($InheritanceType) {
        None { [int][System.Security.AccessControl.AceFlags]::None }
        All { [int][System.Security.AccessControl.AceFlags]::ContainerInherit }
        Descendents {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::InheritOnly
        }
        SelfAndChildren {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
        }
        Children {
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
                [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
        }
    }
    [System.Security.AccessControl.AceFlags]$flags
}
