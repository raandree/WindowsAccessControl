function Test-WindowsCngKeyDaclEquivalent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [Security.AccessControl.RawSecurityDescriptor]$Left,

        [Parameter(Mandatory)]
        [AllowNull()]
        [Security.AccessControl.RawSecurityDescriptor]$Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    $leftProtected = ([int]$Left.ControlFlags -band
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    $rightProtected = ([int]$Right.ControlFlags -band
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    if ($leftProtected -ne $rightProtected) {
        return $false
    }

    $leftKeys = @(ConvertTo-WindowsCngKeyAceKey -Acl $Left.DiscretionaryAcl)
    $rightKeys = @(ConvertTo-WindowsCngKeyAceKey -Acl $Right.DiscretionaryAcl)
    if ($leftKeys.Count -ne $rightKeys.Count) {
        return $false
    }
    $leftOrdered = @($leftKeys | Sort-Object)
    $rightOrdered = @($rightKeys | Sort-Object)
    for ($index = 0; $index -lt $leftOrdered.Count; $index++) {
        if ($leftOrdered[$index] -cne $rightOrdered[$index]) {
            return $false
        }
    }
    $true
}
