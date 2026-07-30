function Assert-WindowsADDistinguishedNameInput {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$DistinguishedName
    )

    foreach ($value in $DistinguishedName) {
        if ($null -eq $value) {
            throw 'DistinguishedName cannot contain a null value.'
        }
        if ($value -is [string]) {
            continue
        }
        $typeNames = @($value.PSObject.TypeNames)
        if ($typeNames -contains 'WindowsAccessControl.ADObjectAccessRule' -or
            $typeNames -contains 'WindowsAccessControl.ADObjectSecurityDescriptor') {
            throw (
                'DistinguishedName does not accept a module result object. Pipe ' +
                'a rule to Remove-ADObjectAccessRule without -Account for exact ' +
                'removal, or pass the distinguished name explicitly.'
            )
        }
    }
}
