function ConvertTo-WindowsSecurityDescriptorObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $result = [pscustomobject]@{
        ObjectType               = $Target.ObjectType
        Path                     = $Target.Path
        ShareName                = $Target.ShareName
        Server                   = $Target.Server
        DistinguishedName        = $Target.DistinguishedName
        ObjectGuid               = $Target.ObjectGuid
        DefaultNamingContext     = $Target.DefaultNamingContext
        TaskPath                 = $Target.TaskPath
        TaskName                 = $Target.TaskName
        ProviderName             = $Target.ProviderName
        KeyName                  = $Target.KeyName
        UniqueName               = $Target.UniqueName
        KeyScope                 = $Target.KeyScope
        CertificateThumbprint    = $Target.CertificateThumbprint
        ServiceName              = $Target.ServiceName
        ProcessId                = $Target.ProcessId
        ProcessName              = $Target.ProcessName
        CreationTime             = $Target.CreationTime
        CreationTimeFileTime     = $Target.CreationTimeFileTime
        Handle                   = if ($Target.DescriptorSource -eq 'Handle') {
            $Target.Handle
        } else {
            [IntPtr]::Zero
        }
        NativePath               = $Target.NativePath
        CanonicalTarget          = $Target.CanonicalTarget
        RegistryView             = $Target.RegistryView
        Sections                 = $Sections
        Sddl                     = $null
        OwnerSID                 = $null
        GroupSID                 = $null
        AccessRulesProtected     = $false
        AuditRulesProtected      = $false
        ConcurrencyToken         = $null
        BinarySecurityDescriptor = $SecurityDescriptor
        NativeDescriptor         = $null
    }
    Update-WindowsSecurityDescriptorObject `
        -Descriptor $result `
        -SecurityDescriptor $SecurityDescriptor `
        -RefreshConcurrencyToken
    $result.PSObject.TypeNames.Insert(0, $TypeName)
    $result.PSObject.TypeNames.Add('WindowsAccessControl.SecurityDescriptor')
    $result
}
