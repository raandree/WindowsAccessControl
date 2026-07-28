Set-StrictMode -Version 2.0

function Get-WindowsAccessControlDomainLabPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
        [string]$DomainDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberServer
    )

    $rootOrganizationalUnit = "OU=WindowsAccessControlLab,$DomainDistinguishedName"
    $marker = 'Managed by the WindowsAccessControl disposable domain lab harness.'

    [pscustomobject]@{
        Marker       = $marker
        Domain       = [pscustomobject]@{
            RootOrganizationalUnit = $rootOrganizationalUnit
            OrganizationalUnits    = @(
                [pscustomobject]@{ Name = 'Identities'; Path = $rootOrganizationalUnit }
                [pscustomobject]@{ Name = 'Groups'; Path = $rootOrganizationalUnit }
                [pscustomobject]@{ Name = 'Targets'; Path = $rootOrganizationalUnit }
            )
            Users                   = @(
                [pscustomobject]@{ SamAccountName = 'WacLabOperator'; Role = 'DelegatedOperator' }
                [pscustomobject]@{ SamAccountName = 'WacLabUser'; Role = 'OrdinaryUser' }
                [pscustomobject]@{ SamAccountName = 'WacLabDenied'; Role = 'DeniedIdentity' }
                [pscustomobject]@{ SamAccountName = 'WacLabService'; Role = 'ServiceIdentity' }
            )
            Groups                  = @(
                [pscustomobject]@{ SamAccountName = 'WacLabReaders'; Role = 'ResourceReaders' }
                [pscustomobject]@{ SamAccountName = 'WacLabNested'; Role = 'NestedMembership' }
            )
        }
        MemberServer = [pscustomobject]@{
            ComputerName       = $MemberServer
            RootPath           = 'C:\WindowsAccessControlLab'
            ShareName          = 'WacLab$'
            SharePath          = 'C:\WindowsAccessControlLab\Share'
            TaskFolder         = '\WindowsAccessControlLab'
            CertificateSubject = 'CN=WindowsAccessControl Lab Key'
            CertificateName    = 'WindowsAccessControl Lab Key'
            CertificateProvider = 'Microsoft Software Key Storage Provider'
            CertificateKeyName  = 'WindowsAccessControlLabKey'
        }
    }
}

function Assert-WindowsAccessControlDomainLabMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Actual,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Expected,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )

    if ($Actual -cne $Expected) {
        throw "Refusing to manage unmarked domain-lab resource: $Resource"
    }
}

function Get-WindowsAccessControlDomainLabOrganizationalUnit {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^OU=[^,]+,.+$')]
        [string]$DistinguishedName
    )

    $separatorIndex = $DistinguishedName.IndexOf(',')
    $name = $DistinguishedName.Substring(3, $separatorIndex - 3)
    $path = $DistinguishedName.Substring($separatorIndex + 1)
    Get-ADOrganizationalUnit `
        -LDAPFilter "(ou=$name)" `
        -SearchBase $path `
        -SearchScope OneLevel `
        -Properties Description `
        -ErrorAction Stop |
        Where-Object DistinguishedName -CEQ $DistinguishedName
}

function Initialize-WindowsAccessControlDomainFixture {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Import-Module -Name ActiveDirectory -ErrorAction Stop

    $createdResources = [System.Collections.Generic.List[string]]::new()
    $rootName = 'WindowsAccessControlLab'
    $rootPath = $Plan.Domain.RootOrganizationalUnit.Substring(
        $Plan.Domain.RootOrganizationalUnit.IndexOf(',') + 1
    )
    $rootOrganizationalUnit = Get-WindowsAccessControlDomainLabOrganizationalUnit `
        -DistinguishedName $Plan.Domain.RootOrganizationalUnit

    if ($null -eq $rootOrganizationalUnit) {
        $rootOrganizationalUnit = New-ADOrganizationalUnit `
            -Name $rootName `
            -Path $rootPath `
            -Description $Plan.Marker `
            -ProtectedFromAccidentalDeletion:$false `
            -PassThru `
            -ErrorAction Stop
        $createdResources.Add('DomainRootOrganizationalUnit')
    }
    else {
        Assert-WindowsAccessControlDomainLabMarker `
            -Actual ([string]$rootOrganizationalUnit.Description) `
            -Expected $Plan.Marker `
            -Resource 'domain root organizational unit'
    }

    foreach ($organizationalUnitPlan in $Plan.Domain.OrganizationalUnits) {
        $distinguishedName = "OU=$($organizationalUnitPlan.Name),$($organizationalUnitPlan.Path)"
        $organizationalUnit = Get-WindowsAccessControlDomainLabOrganizationalUnit `
            -DistinguishedName $distinguishedName
        if ($null -eq $organizationalUnit) {
            $null = New-ADOrganizationalUnit `
                -Name $organizationalUnitPlan.Name `
                -Path $organizationalUnitPlan.Path `
                -Description $Plan.Marker `
                -ProtectedFromAccidentalDeletion:$false `
                -PassThru `
                -ErrorAction Stop
            $createdResources.Add("DomainOrganizationalUnit:$($organizationalUnitPlan.Name)")
        }
        else {
            Assert-WindowsAccessControlDomainLabMarker `
                -Actual ([string]$organizationalUnit.Description) `
                -Expected $Plan.Marker `
                -Resource "domain organizational unit $($organizationalUnitPlan.Name)"
        }
    }

    $identityPath = "OU=Identities,$($Plan.Domain.RootOrganizationalUnit)"
    foreach ($userPlan in $Plan.Domain.Users) {
        $users = @(
            Get-ADUser `
            -LDAPFilter "(sAMAccountName=$($userPlan.SamAccountName))" `
            -SearchBase $rootPath `
            -SearchScope Subtree `
            -Properties Description `
            -ErrorAction Stop
        )
        if ($users.Count -gt 1) {
            throw "Multiple directory users use the domain-lab account name: $($userPlan.SamAccountName)"
        }
        $user = $users | Select-Object -First 1
        $expectedDistinguishedName = "CN=$($userPlan.SamAccountName),$identityPath"
        if ($null -eq $user) {
            $null = New-ADUser `
                -Name $userPlan.SamAccountName `
                -SamAccountName $userPlan.SamAccountName `
                -Path $identityPath `
                -Description $Plan.Marker `
                -Enabled:$false `
                -PassThru `
                -ErrorAction Stop
            $createdResources.Add("DomainUser:$($userPlan.SamAccountName)")
        }
        else {
            if ($user.DistinguishedName -cne $expectedDistinguishedName) {
                throw "Refusing to reuse domain-lab identity outside the test OU: $($userPlan.SamAccountName)"
            }
            Assert-WindowsAccessControlDomainLabMarker `
                -Actual ([string]$user.Description) `
                -Expected $Plan.Marker `
                -Resource "domain user $($userPlan.SamAccountName)"
        }
    }

    $groupPath = "OU=Groups,$($Plan.Domain.RootOrganizationalUnit)"
    foreach ($groupPlan in $Plan.Domain.Groups) {
        $groups = @(
            Get-ADGroup `
            -LDAPFilter "(sAMAccountName=$($groupPlan.SamAccountName))" `
            -SearchBase $rootPath `
            -SearchScope Subtree `
            -Properties Description `
            -ErrorAction Stop
        )
        if ($groups.Count -gt 1) {
            throw "Multiple directory groups use the domain-lab account name: $($groupPlan.SamAccountName)"
        }
        $group = $groups | Select-Object -First 1
        $expectedDistinguishedName = "CN=$($groupPlan.SamAccountName),$groupPath"
        if ($null -eq $group) {
            $null = New-ADGroup `
                -Name $groupPlan.SamAccountName `
                -SamAccountName $groupPlan.SamAccountName `
                -Path $groupPath `
                -Description $Plan.Marker `
                -GroupCategory Security `
                -GroupScope Global `
                -PassThru `
                -ErrorAction Stop
            $createdResources.Add("DomainGroup:$($groupPlan.SamAccountName)")
        }
        else {
            if ($group.DistinguishedName -cne $expectedDistinguishedName) {
                throw "Refusing to reuse domain-lab group outside the test OU: $($groupPlan.SamAccountName)"
            }
            Assert-WindowsAccessControlDomainLabMarker `
                -Actual ([string]$group.Description) `
                -Expected $Plan.Marker `
                -Resource "domain group $($groupPlan.SamAccountName)"
        }
    }

    $memberships = @(
        [pscustomobject]@{ Group = 'WacLabNested'; Member = 'WacLabUser'; MemberType = 'User' }
        [pscustomobject]@{ Group = 'WacLabReaders'; Member = 'WacLabNested'; MemberType = 'Group' }
    )
    foreach ($membership in $memberships) {
        $member = if ($membership.MemberType -eq 'User') {
            Get-ADUser -Identity $membership.Member -ErrorAction Stop
        }
        else {
            Get-ADGroup -Identity $membership.Member -ErrorAction Stop
        }
        $memberExists = Get-ADGroupMember -Identity $membership.Group -ErrorAction Stop |
            Where-Object { $_.SID -eq $member.SID }
        if ($null -eq $memberExists) {
            Add-ADGroupMember `
                -Identity $membership.Group `
                -Members $membership.Member `
                -ErrorAction Stop
            $createdResources.Add("DomainMembership:$($membership.Group)<-$($membership.Member)")
        }
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $recoverySid = "$($domain.DomainSID.Value)-500"
    $domainAdministratorsSid = "$($domain.DomainSID.Value)-512"
    $recoveryIdentity = Get-ADUser `
        -Identity $recoverySid `
        -Properties Enabled `
        -ErrorAction Stop
    $recoveryIsDomainAdministrator = Get-ADGroupMember `
        -Identity $domainAdministratorsSid `
        -Recursive `
        -ErrorAction Stop |
        Where-Object { $_.SID -eq $recoveryIdentity.SID }
    if (-not $recoveryIdentity.Enabled -or $null -eq $recoveryIsDomainAdministrator) {
        throw 'The untouched RID-500 recovery identity is not enabled with domain recovery authority.'
    }

    [pscustomobject]@{
        Boundary                    = 'DomainController'
        CreatedResources            = $createdResources.ToArray()
        CreatedCount                = $createdResources.Count
        RecoveryIdentityVerified    = $true
        RecoveryIdentityWasModified = $false
    }
}

function Initialize-WindowsAccessControlMemberFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseUsingScopeModifierInNewRunspaces',
        '',
        Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Invoke-Command `
        -ComputerName $Plan.MemberServer.ComputerName `
        -Authentication Kerberos `
        -ArgumentList $Plan.MemberServer, $Plan.Marker `
        -ErrorAction Stop `
        -ScriptBlock {
            param($MemberPlan, $Marker)

            $ErrorActionPreference = 'Stop'
            $createdResources = [System.Collections.Generic.List[string]]::new()
            $markerPath = Join-Path -Path $MemberPlan.RootPath -ChildPath '.windows-access-control-lab'

            if (Test-Path -LiteralPath $MemberPlan.RootPath) {
                if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
                    throw 'Refusing to reuse an unmarked member-server lab directory.'
                }
                $actualMarker = Get-Content -LiteralPath $markerPath -Raw
                if ($actualMarker.TrimEnd() -cne $Marker) {
                    throw 'Refusing to reuse a member-server lab directory with an invalid marker.'
                }
            }
            else {
                $null = New-Item -Path $MemberPlan.RootPath -ItemType Directory -ErrorAction Stop
                try {
                    [IO.File]::WriteAllText(
                        $markerPath,
                        $Marker,
                        [Text.UTF8Encoding]::new($false)
                    )
                }
                catch {
                    $markerError = $_
                    try {
                        Remove-Item `
                            -LiteralPath $MemberPlan.RootPath `
                            -Recurse `
                            -Force `
                            -ErrorAction Stop
                    }
                    catch {
                        throw [AggregateException]::new(
                            'Member-server marker creation and cleanup both failed.',
                            [Exception[]]@($markerError.Exception, $_.Exception)
                        )
                    }
                    throw $markerError
                }
                $createdResources.Add('MemberRootDirectory')
            }

            if (-not (Test-Path -LiteralPath $MemberPlan.SharePath -PathType Container)) {
                $null = New-Item -Path $MemberPlan.SharePath -ItemType Directory -ErrorAction Stop
                $createdResources.Add('MemberShareDirectory')
            }

            $share = Get-SmbShare -Name $MemberPlan.ShareName -ErrorAction SilentlyContinue
            if ($null -eq $share) {
                $administrators = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate(
                    [Security.Principal.NTAccount]
                ).Value
                $null = New-SmbShare `
                    -Name $MemberPlan.ShareName `
                    -Path $MemberPlan.SharePath `
                    -Description $Marker `
                    -FullAccess $administrators `
                    -ErrorAction Stop
                $createdResources.Add('MemberSmbShare')
            }
            elseif (
                $share.Path -cne $MemberPlan.SharePath -or
                $share.Description -cne $Marker
            ) {
                throw 'Refusing to reuse an SMB share that is not owned by the domain-lab harness.'
            }

            $taskService = $null
            $taskRoot = $null
            $taskFolder = $null
            try {
                $taskService = New-Object -ComObject 'Schedule.Service'
                $taskService.Connect()
                $taskRoot = $taskService.GetFolder('\')
                try {
                    $taskFolder = $taskService.GetFolder($MemberPlan.TaskFolder)
                }
                catch {
                    if ($_.Exception.HResult -ne -2147024894) {
                        throw
                    }
                    $taskFolder = $taskRoot.CreateFolder(
                        $MemberPlan.TaskFolder.TrimStart('\'),
                        $null
                    )
                    $createdResources.Add('MemberTaskFolder')
                }
            }
            finally {
                foreach ($comObject in @($taskFolder, $taskRoot, $taskService)) {
                    if ($null -ne $comObject) {
                        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                    }
                }
            }

            $certificates = @(
                Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                    Where-Object {
                        $_.Subject -ceq $MemberPlan.CertificateSubject -and
                        $_.FriendlyName -ceq $MemberPlan.CertificateName
                    }
            )
            if ($certificates.Count -gt 1) {
                throw 'Multiple domain-lab certificates have the same managed identity.'
            }
            $certificateNeedsCreation = $certificates.Count -eq 0
            if ($certificates.Count -eq 1) {
                $certificate = $certificates[0]
                $certificateIsOrphaned = -not $certificate.HasPrivateKey
                $privateKey = $null
                if (-not $certificateIsOrphaned) {
                    try {
                        $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                            GetRSAPrivateKey($certificate)
                    }
                    catch [Security.Cryptography.CryptographicException] {
                        $certificateIsOrphaned = $true
                    }
                }

                if ($null -ne $privateKey) {
                    try {
                        if (
                            $privateKey.GetType().FullName -cne 'System.Security.Cryptography.RSACng' -or
                            $privateKey.Key.KeyName -cne $MemberPlan.CertificateKeyName -or
                            $privateKey.Key.Provider.Provider -cne $MemberPlan.CertificateProvider
                        ) {
                            throw 'A matching certificate does not use the managed CNG provider and container.'
                        }
                    }
                    finally {
                        $privateKey.Dispose()
                    }
                }
                elseif (-not $certificateIsOrphaned) {
                    $certificateIsOrphaned = $true
                }

                if ($certificateIsOrphaned) {
                    Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
                    $certificateNeedsCreation = $true
                }
            }
            if ($certificateNeedsCreation) {
                $provider = [Security.Cryptography.CngProvider]::new(
                    $MemberPlan.CertificateProvider
                )
                $keyOpenOptions = [Security.Cryptography.CngKeyOpenOptions]::MachineKey
                if ([Security.Cryptography.CngKey]::Exists(
                        $MemberPlan.CertificateKeyName,
                        $provider,
                        $keyOpenOptions
                    )) {
                    $orphanedKey = [Security.Cryptography.CngKey]::Open(
                        $MemberPlan.CertificateKeyName,
                        $provider,
                        $keyOpenOptions
                    )
                    try {
                        $orphanedKey.Delete()
                    }
                    finally {
                        $orphanedKey.Dispose()
                    }
                }
                $null = New-SelfSignedCertificate `
                    -Subject $MemberPlan.CertificateSubject `
                    -FriendlyName $MemberPlan.CertificateName `
                    -CertStoreLocation 'Cert:\LocalMachine\My' `
                    -Provider $MemberPlan.CertificateProvider `
                    -Container $MemberPlan.CertificateKeyName `
                    -KeyAlgorithm RSA `
                    -KeyLength 2048 `
                    -HashAlgorithm SHA256 `
                    -KeyExportPolicy NonExportable `
                    -KeyUsage DigitalSignature `
                    -NotAfter (Get-Date).AddDays(30) `
                    -ErrorAction Stop
                $createdResources.Add('MemberCertificateKey')
            }

            [pscustomobject]@{
                Boundary         = 'MemberServer'
                CreatedResources = $createdResources.ToArray()
                CreatedCount     = $createdResources.Count
            }
        }
}

function Test-WindowsAccessControlDomainLabObjectSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter()]
        [AllowNull()]
        [object]$Root,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Objects,

        [Parameter(Mandatory)]
        [bool]$RecoveryIdentityReady
    )

    $expectedObjectCount = 1 +
        $Plan.Domain.OrganizationalUnits.Count +
        $Plan.Domain.Users.Count +
        $Plan.Domain.Groups.Count
    $markedObjectCount = @(
        $Objects | Where-Object Description -CEQ $Plan.Marker
    ).Count
    $rootPresent = $null -ne $Root
    $rootMarked = $rootPresent -and $Root.Description -ceq $Plan.Marker

    [pscustomobject]@{
        RootPresent          = $rootPresent
        RootMarked           = $rootMarked
        ExpectedObjectCount  = $expectedObjectCount
        ObjectCount          = $Objects.Count
        MarkedObjectCount    = $markedObjectCount
        RecoveryIdentityReady = $RecoveryIdentityReady
        Ready                = (
            $rootMarked -and
            $Objects.Count -eq $expectedObjectCount -and
            $markedObjectCount -eq $Objects.Count -and
            $RecoveryIdentityReady
        )
    }
}

function Test-WindowsAccessControlDomainFixture {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Import-Module -Name ActiveDirectory -ErrorAction Stop

    $root = Get-WindowsAccessControlDomainLabOrganizationalUnit `
        -DistinguishedName $Plan.Domain.RootOrganizationalUnit
    $objects = @()
    if ($null -ne $root) {
        $objects = @(
            Get-ADObject `
                -SearchBase $Plan.Domain.RootOrganizationalUnit `
                -SearchScope Subtree `
                -LDAPFilter '(objectClass=*)' `
                -Properties Description `
                -ErrorAction Stop
        )
    }
    $domain = Get-ADDomain -ErrorAction Stop
    $recoverySid = "$($domain.DomainSID.Value)-500"
    $domainAdministratorsSid = "$($domain.DomainSID.Value)-512"
    $recoveryIdentity = Get-ADUser `
        -Identity $recoverySid `
        -Properties Enabled `
        -ErrorAction Stop
    $recoveryMembership = Get-ADGroupMember `
        -Identity $domainAdministratorsSid `
        -Recursive `
        -ErrorAction Stop |
        Where-Object SID -EQ $recoveryIdentity.SID
    $recoveryIdentityReady = $recoveryIdentity.Enabled -and $null -ne $recoveryMembership
    $objectSet = Test-WindowsAccessControlDomainLabObjectSet `
        -Plan $Plan `
        -Root $root `
        -Objects $objects `
        -RecoveryIdentityReady $recoveryIdentityReady

    [pscustomobject]@{
        Boundary              = 'DomainController'
        RootPresent           = $objectSet.RootPresent
        RootMarked            = $objectSet.RootMarked
        ExpectedObjectCount   = $objectSet.ExpectedObjectCount
        ObjectCount           = $objectSet.ObjectCount
        MarkedObjectCount     = $objectSet.MarkedObjectCount
        RecoveryIdentityReady = $objectSet.RecoveryIdentityReady
        Ready                 = $objectSet.Ready
    }
}

function Test-WindowsAccessControlMemberFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseUsingScopeModifierInNewRunspaces',
        '',
        Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Invoke-Command `
        -ComputerName $Plan.MemberServer.ComputerName `
        -Authentication Kerberos `
        -ArgumentList $Plan.MemberServer, $Plan.Marker `
        -ErrorAction Stop `
        -ScriptBlock {
            param($MemberPlan, $Marker)

            $ErrorActionPreference = 'Stop'
            $markerPath = Join-Path -Path $MemberPlan.RootPath -ChildPath '.windows-access-control-lab'
            $markerValid = if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
                (Get-Content -LiteralPath $markerPath -Raw).TrimEnd() -ceq $Marker
            }
            else {
                $false
            }

            $share = Get-SmbShare -Name $MemberPlan.ShareName -ErrorAction SilentlyContinue
            $shareReady = $null -ne $share -and
                $share.Path -ceq $MemberPlan.SharePath -and
                $share.Description -ceq $Marker

            $taskFolderPresent = $false
            $taskService = $null
            $taskFolder = $null
            try {
                $taskService = New-Object -ComObject 'Schedule.Service'
                $taskService.Connect()
                try {
                    $taskFolder = $taskService.GetFolder($MemberPlan.TaskFolder)
                    $taskFolderPresent = $null -ne $taskFolder
                }
                catch {
                    if ($_.Exception.HResult -ne -2147024894) {
                        throw
                    }
                }
            }
            finally {
                foreach ($comObject in @($taskFolder, $taskService)) {
                    if ($null -ne $comObject) {
                        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                    }
                }
            }

            $certificates = @(
                Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                    Where-Object {
                        $_.Subject -ceq $MemberPlan.CertificateSubject -and
                        $_.FriendlyName -ceq $MemberPlan.CertificateName
                    }
            )
            $certificateReady = $false
            if ($certificates.Count -eq 1 -and $certificates[0].HasPrivateKey) {
                $privateKey = $null
                try {
                    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                        GetRSAPrivateKey($certificates[0])
                    $certificateReady = (
                        $null -ne $privateKey -and
                        $privateKey.GetType().FullName -ceq 'System.Security.Cryptography.RSACng' -and
                        $privateKey.Key.KeyName -ceq $MemberPlan.CertificateKeyName -and
                        $privateKey.Key.Provider.Provider -ceq $MemberPlan.CertificateProvider
                    )
                }
                catch [Security.Cryptography.CryptographicException] {
                    $certificateReady = $false
                }
                finally {
                    if ($null -ne $privateKey) {
                        $privateKey.Dispose()
                    }
                }
            }

            [pscustomobject]@{
                Boundary            = 'MemberServer'
                MarkerReady         = $markerValid
                ShareDirectoryReady = Test-Path -LiteralPath $MemberPlan.SharePath -PathType Container
                ShareReady          = $shareReady
                TaskFolderReady     = $taskFolderPresent
                CertificateReady    = $certificateReady
                Ready               = (
                    $markerValid -and
                    (Test-Path -LiteralPath $MemberPlan.SharePath -PathType Container) -and
                    $shareReady -and
                    $taskFolderPresent -and
                    $certificateReady
                )
            }
        }
}

function Remove-WindowsAccessControlDomainFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this cleanup boundary.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Import-Module -Name ActiveDirectory -ErrorAction Stop

    $root = Get-WindowsAccessControlDomainLabOrganizationalUnit `
        -DistinguishedName $Plan.Domain.RootOrganizationalUnit
    if ($null -eq $root) {
        return [pscustomobject]@{
            Boundary      = 'DomainController'
            Removed       = $false
            AlreadyAbsent = $true
        }
    }

    Assert-WindowsAccessControlDomainLabMarker `
        -Actual ([string]$root.Description) `
        -Expected $Plan.Marker `
        -Resource 'domain root organizational unit'
    $children = @(
        Get-ADObject `
            -SearchBase $Plan.Domain.RootOrganizationalUnit `
            -SearchScope Subtree `
            -LDAPFilter '(objectClass=*)' `
            -Properties Description `
            -ErrorAction Stop
    )
    $unmarkedChildren = @($children | Where-Object Description -CNE $Plan.Marker)
    if ($unmarkedChildren.Count -gt 0) {
        throw 'Refusing to remove a domain-lab OU that contains unmarked objects.'
    }

    Get-ADOrganizationalUnit `
        -SearchBase $Plan.Domain.RootOrganizationalUnit `
        -SearchScope Subtree `
        -Filter * `
        -ErrorAction Stop |
        Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion:$false -ErrorAction Stop
    Set-ADOrganizationalUnit `
        -Identity $Plan.Domain.RootOrganizationalUnit `
        -ProtectedFromAccidentalDeletion:$false `
        -ErrorAction Stop
    Remove-ADOrganizationalUnit `
        -Identity $Plan.Domain.RootOrganizationalUnit `
        -Recursive `
        -Confirm:$false `
        -ErrorAction Stop

    [pscustomobject]@{
        Boundary      = 'DomainController'
        Removed       = $true
        AlreadyAbsent = $false
    }
}

function Remove-WindowsAccessControlMemberFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseUsingScopeModifierInNewRunspaces',
        '',
        Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this cleanup boundary.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Invoke-Command `
        -ComputerName $Plan.MemberServer.ComputerName `
        -Authentication Kerberos `
        -ArgumentList $Plan.MemberServer, $Plan.Marker `
        -ErrorAction Stop `
        -ScriptBlock {
            param($MemberPlan, $Marker)

            $ErrorActionPreference = 'Stop'
            $markerPath = Join-Path -Path $MemberPlan.RootPath -ChildPath '.windows-access-control-lab'
            $rootPresent = Test-Path -LiteralPath $MemberPlan.RootPath -PathType Container
            $share = Get-SmbShare -Name $MemberPlan.ShareName -ErrorAction SilentlyContinue
            $certificates = @(
                Get-ChildItem -Path 'Cert:\LocalMachine\My' |
                    Where-Object {
                        $_.Subject -ceq $MemberPlan.CertificateSubject -and
                        $_.FriendlyName -ceq $MemberPlan.CertificateName
                    }
            )
            if ($certificates.Count -gt 1) {
                throw 'Refusing to remove multiple certificates with the managed display identity.'
            }

            $taskService = $null
            $taskRoot = $null
            $taskFolder = $null
            $taskFolderPresent = $false
            try {
                $taskService = New-Object -ComObject 'Schedule.Service'
                $taskService.Connect()
                $taskRoot = $taskService.GetFolder('\')
                try {
                    $taskFolder = $taskService.GetFolder($MemberPlan.TaskFolder)
                    $taskFolderPresent = $true
                }
                catch {
                    if ($_.Exception.HResult -ne -2147024894) {
                        throw
                    }
                }

                if (-not $rootPresent) {
                    if ($null -ne $share -or $certificates.Count -gt 0 -or $taskFolderPresent) {
                        throw 'Refusing to remove member-server fixtures without their ownership marker.'
                    }
                    return [pscustomobject]@{
                        Boundary      = 'MemberServer'
                        Removed       = $false
                        AlreadyAbsent = $true
                    }
                }

                if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
                    throw 'Refusing to remove an unmarked member-server lab directory.'
                }
                if ((Get-Content -LiteralPath $markerPath -Raw).TrimEnd() -cne $Marker) {
                    throw 'Refusing to remove a member-server lab directory with an invalid marker.'
                }

                if ($null -ne $share) {
                    if ($share.Path -cne $MemberPlan.SharePath -or $share.Description -cne $Marker) {
                        throw 'Refusing to remove an SMB share that is not owned by the domain-lab harness.'
                    }
                    Remove-SmbShare -Name $MemberPlan.ShareName -Force -Confirm:$false -ErrorAction Stop
                }

                if ($taskFolderPresent) {
                    if ($taskFolder.GetTasks(0).Count -gt 0 -or $taskFolder.GetFolders(0).Count -gt 0) {
                        throw 'Refusing to remove a non-empty domain-lab task folder.'
                    }
                    $taskRoot.DeleteFolder($MemberPlan.TaskFolder.TrimStart('\'), 0)
                }
            }
            finally {
                foreach ($comObject in @($taskFolder, $taskRoot, $taskService)) {
                    if ($null -ne $comObject) {
                        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
                    }
                }
            }

            if ($certificates.Count -eq 1) {
                $certificate = $certificates[0]
                $privateKey = $null
                if ($certificate.HasPrivateKey) {
                    try {
                        $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                            GetRSAPrivateKey($certificate)
                    }
                    catch [Security.Cryptography.CryptographicException] {
                        $privateKey = $null
                    }
                }
                if ($null -ne $privateKey) {
                    try {
                        if (
                            $privateKey.GetType().FullName -cne 'System.Security.Cryptography.RSACng' -or
                            $privateKey.Key.KeyName -cne $MemberPlan.CertificateKeyName -or
                            $privateKey.Key.Provider.Provider -cne $MemberPlan.CertificateProvider
                        ) {
                            throw 'Refusing to delete a certificate key outside the managed CNG container.'
                        }
                        $privateKey.Key.Delete()
                    }
                    finally {
                        $privateKey.Dispose()
                    }
                }
                Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
            }
            $provider = [Security.Cryptography.CngProvider]::new(
                $MemberPlan.CertificateProvider
            )
            $keyOpenOptions = [Security.Cryptography.CngKeyOpenOptions]::MachineKey
            if ([Security.Cryptography.CngKey]::Exists(
                    $MemberPlan.CertificateKeyName,
                    $provider,
                    $keyOpenOptions
                )) {
                $remainingKey = [Security.Cryptography.CngKey]::Open(
                    $MemberPlan.CertificateKeyName,
                    $provider,
                    $keyOpenOptions
                )
                try {
                    $remainingKey.Delete()
                }
                finally {
                    $remainingKey.Dispose()
                }
            }
            Remove-Item -LiteralPath $MemberPlan.RootPath -Recurse -Force -ErrorAction Stop

            [pscustomobject]@{
                Boundary      = 'MemberServer'
                Removed       = $true
                AlreadyAbsent = $false
            }
        }
}

function Initialize-WindowsAccessControlDomainLab {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
        [string]$DomainDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberServer
    )

    $plan = Get-WindowsAccessControlDomainLabPlan `
        -DomainDistinguishedName $DomainDistinguishedName `
        -MemberServer $MemberServer
    $domainResult = $null
    $memberResult = $null
    $domainInitializationStarted = $false
    $memberInitializationStarted = $false

    try {
        if ($PSCmdlet.ShouldProcess(
                $plan.Domain.RootOrganizationalUnit,
                'Initialize disposable domain fixtures'
            )) {
            $domainInitializationStarted = $true
            $domainResult = Initialize-WindowsAccessControlDomainFixture -Plan $plan
        }
        if ($PSCmdlet.ShouldProcess(
                $plan.MemberServer.ComputerName,
                'Initialize disposable member-server fixtures'
            )) {
            $memberInitializationStarted = $true
            $memberResult = Initialize-WindowsAccessControlMemberFixture -Plan $plan
        }
    }
    catch {
        $initializationError = $_
        $cleanupErrors = [System.Collections.Generic.List[Exception]]::new()

        if ($memberInitializationStarted) {
            try {
                $null = Remove-WindowsAccessControlMemberFixture `
                    -Plan $plan
            }
            catch {
                $cleanupErrors.Add($_.Exception)
            }
        }
        if ($domainInitializationStarted) {
            try {
                $null = Remove-WindowsAccessControlDomainFixture `
                    -Plan $plan
            }
            catch {
                $cleanupErrors.Add($_.Exception)
            }
        }

        if ($cleanupErrors.Count -eq 0) {
            throw $initializationError
        }

        $allErrors = [System.Collections.Generic.List[Exception]]::new()
        $allErrors.Add($initializationError.Exception)
        $allErrors.AddRange($cleanupErrors)
        throw [AggregateException]::new(
            "Domain-lab initialization and compensating cleanup failed: $($initializationError.Exception.Message)",
            $allErrors
        )
    }

    [pscustomobject]@{
        DomainController = $domainResult
        MemberServer     = $memberResult
    }
}

function Test-WindowsAccessControlDomainLab {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
        [string]$DomainDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberServer
    )

    $plan = Get-WindowsAccessControlDomainLabPlan `
        -DomainDistinguishedName $DomainDistinguishedName `
        -MemberServer $MemberServer
    $domainResult = Test-WindowsAccessControlDomainFixture -Plan $plan
    $memberResult = Test-WindowsAccessControlMemberFixture -Plan $plan

    [pscustomobject]@{
        Ready            = $domainResult.Ready -and $memberResult.Ready
        DomainController = $domainResult
        MemberServer     = $memberResult
    }
}

function Remove-WindowsAccessControlDomainLab {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
        [string]$DomainDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberServer
    )

    $plan = Get-WindowsAccessControlDomainLabPlan `
        -DomainDistinguishedName $DomainDistinguishedName `
        -MemberServer $MemberServer
    $memberResult = $null
    $domainResult = $null

    if ($PSCmdlet.ShouldProcess(
            $plan.MemberServer.ComputerName,
            'Remove disposable member-server fixtures'
        )) {
        $memberResult = Remove-WindowsAccessControlMemberFixture -Plan $plan
    }
    if ($PSCmdlet.ShouldProcess(
            $plan.Domain.RootOrganizationalUnit,
            'Remove disposable domain fixtures'
        )) {
        $domainResult = Remove-WindowsAccessControlDomainFixture -Plan $plan
    }

    [pscustomobject]@{
        DomainController = $domainResult
        MemberServer     = $memberResult
    }
}

function Write-WindowsAccessControlDomainLabAcceptanceEvidence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The public acceptance runner enforces ShouldProcess before writing evidence.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Summary,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string[]]$SensitiveValues
    )

    $fullPath = [IO.Path]::GetFullPath($OutputPath)
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($directory) -and
        -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new(
            "The acceptance evidence directory does not exist: '$directory'."
        )
    }

    $json = $Summary | ConvertTo-Json -Depth 8
    foreach ($sensitiveValue in $SensitiveValues) {
        if (-not [string]::IsNullOrWhiteSpace($sensitiveValue) -and
            $json.IndexOf(
                $sensitiveValue,
                [StringComparison]::OrdinalIgnoreCase
            ) -ge 0) {
            throw [InvalidOperationException]::new(
                'The retained domain-lab evidence contains an infrastructure identifier.'
            )
        }
    }

    $temporaryPath = Join-Path -Path $directory -ChildPath (
        '.{0}.{1}.tmp' -f [IO.Path]::GetFileName($fullPath), [guid]::NewGuid()
    )
    $rollbackPath = Join-Path -Path $directory -ChildPath (
        '.{0}.{1}.bak' -f [IO.Path]::GetFileName($fullPath), [guid]::NewGuid()
    )
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            $json + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $fullPath, $rollbackPath)
        }
        else {
            try {
                [IO.File]::Move($temporaryPath, $fullPath)
            }
            catch [IO.IOException] {
                if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                    [IO.File]::Replace($temporaryPath, $fullPath, $rollbackPath)
                }
                else {
                    throw
                }
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $rollbackPath -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-WindowsAccessControlDomainLabEvidenceText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter()]
        [string[]]$SensitiveValues = @()
    )

    $sanitized = $Text
    foreach ($sensitiveValue in @(
            $SensitiveValues |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object Length -Descending -Unique
        )) {
        $sanitized = [regex]::Replace(
            $sanitized,
            [regex]::Escape($sensitiveValue),
            '<redacted>',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }
    $patterns = [ordered]@{
        '(?i)\\\\[^\\\s]+\\[^\s]+' = '<unc-target>'
        '(?i)\bS-\d-\d+(?:-\d+)+\b' = '<sid>'
        '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b' = '<dns-name>'
        '\b(?:\d{1,3}\.){3}\d{1,3}\b' = '<ip-address>'
        '(?i)\b[0-9a-f]{40}\b' = '<thumbprint>'
        '(?i)(?:CN|OU|DC)=[^,\r\n]+(?:,(?:CN|OU|DC)=[^,\r\n]+)*' = '<distinguished-name>'
        '(?i)\b[A-Z]:\\[^\r\n]+' = '<local-path>'
    }
    foreach ($pattern in $patterns.Keys) {
        $sanitized = [regex]::Replace(
            $sanitized,
            $pattern,
            $patterns[$pattern]
        )
    }
    $sanitized
}

function Invoke-WindowsAccessControlDomainLabAcceptance {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [string]$RepositoryRoot,

        [Parameter(Mandatory)]
        [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
        [string]$DomainDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberServer,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    $repositoryPath = (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath
    $repositoryManifest = Join-Path `
        $repositoryPath `
        'source\WindowsAccessControl.psd1'
    if (-not (Test-Path -LiteralPath $repositoryManifest -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new(
            'RepositoryRoot does not contain the WindowsAccessControl source manifest.'
        )
    }
    $suiteNames = @(
        'WindowsAccessControl.DomainLab.Live.Tests.ps1'
        'CertificatePrivateKeyPermissions.Live.Tests.ps1'
        'TaskSchedulerPermissions.Live.Tests.ps1'
        'SmbSharePermissions.Live.Tests.ps1'
        'ADObjectPermissions.Live.Tests.ps1'
    )
    $suitePaths = @(
        foreach ($suiteName in $suiteNames) {
            $suitePath = Join-Path $repositoryPath "tests\Lab\$suiteName"
            if (-not (Test-Path -LiteralPath $suitePath -PathType Leaf)) {
                throw [IO.FileNotFoundException]::new(
                    "The required domain-lab suite does not exist: '$suiteName'."
                )
            }
            $suitePath
        }
    )

    if (-not $PSCmdlet.ShouldProcess(
            'Disposable WindowsAccessControl domain lab',
            "Run acceptance suites and write redacted evidence to '$OutputPath'"
        )) {
        return
    }

    if (-not (Get-Command -Name Invoke-Pester -ErrorAction SilentlyContinue)) {
        Import-Module -Name Pester -MinimumVersion 5.7.1 -ErrorAction Stop
    }

    $harnessModulePath = $MyInvocation.MyCommand.Module.Path
    $labPlan = Get-WindowsAccessControlDomainLabPlan `
        -DomainDistinguishedName $DomainDistinguishedName `
        -MemberServer $MemberServer
    $sensitiveValues = @(
        $DomainDistinguishedName
        $MemberServer
        $labPlan.Domain.RootOrganizationalUnit
        $labPlan.MemberServer.ComputerName
        $labPlan.MemberServer.ShareName
        $labPlan.MemberServer.SharePath
        $labPlan.MemberServer.TaskFolder
        $labPlan.MemberServer.CertificateSubject
        $labPlan.MemberServer.CertificateName
        $labPlan.MemberServer.CertificateKeyName
    )
    $writeEvidence = (Get-Command `
        -Name Write-WindowsAccessControlDomainLabAcceptanceEvidence `
        -CommandType Function `
        -ErrorAction Stop).ScriptBlock
    $sanitizeEvidenceText = (Get-Command `
        -Name ConvertTo-WindowsAccessControlDomainLabEvidenceText `
        -CommandType Function `
        -ErrorAction Stop).ScriptBlock
    $startedAtUtc = [datetime]::UtcNow
    $suiteResults = [Collections.Generic.List[object]]::new()
    $cleanupLedger = [Collections.Generic.List[object]]::new()
    $previousMemberServer = $env:WAC_DOMAIN_LAB_MEMBER
    $summary = $null
    $terminalError = $null
    $secondaryErrors = [Collections.Generic.List[Exception]]::new()
    try {
        $env:WAC_DOMAIN_LAB_MEMBER = $MemberServer
        foreach ($suitePath in $suitePaths) {
            $suiteName = [IO.Path]::GetFileName($suitePath)
            $suiteStartedAtUtc = [datetime]::UtcNow
            Write-Information (
                '[{0:O}] SUITE START {1}' -f $suiteStartedAtUtc, $suiteName
            ) -InformationAction Continue

            $pesterResult = Invoke-Pester `
                -Path $suitePath `
                -Output Detailed `
                -PassThru
            $skips = @(
                foreach ($test in @($pesterResult.Tests)) {
                    if ([string]$test.Result -eq 'Skipped') {
                        $reason = @(
                            @($test.ErrorRecord.Exception.Message) |
                                Where-Object {
                                    -not [string]::IsNullOrWhiteSpace($_)
                                }
                        )
                        $reasonText = if ($reason.Count -gt 0) {
                            [string]$reason[0]
                        }
                        else {
                            'No skip reason was reported.'
                        }
                        [pscustomobject]@{
                            Test   = [string]$test.ExpandedName
                            Reason = & $sanitizeEvidenceText `
                                -Text $reasonText `
                                -SensitiveValues $sensitiveValues
                        }
                    }
                }
            )
            $suiteResult = [pscustomobject]@{
                Suite         = $suiteName
                Result        = [string]$pesterResult.Result
                TotalCount    = [int]$pesterResult.TotalCount
                PassedCount   = [int]$pesterResult.PassedCount
                FailedCount   = [int]$pesterResult.FailedCount
                SkippedCount  = [int]$pesterResult.SkippedCount
                DurationMs    = [math]::Round(
                    [double]$pesterResult.Duration.TotalMilliseconds,
                    2
                )
                SkipReasons   = $skips
                StartedAtUtc  = $suiteStartedAtUtc.ToString('O')
                CompletedAtUtc = [datetime]::UtcNow.ToString('O')
            }
            $suiteResults.Add($suiteResult)

            $labStatus = Test-WindowsAccessControlDomainLab `
                -DomainDistinguishedName $DomainDistinguishedName `
                -MemberServer $MemberServer
            $cleanupResult = [pscustomobject]@{
                Suite               = $suiteName
                Ready               = [bool]$labStatus.Ready
                DomainBoundaryReady = [bool]$labStatus.DomainController.Ready
                MemberBoundaryReady = [bool]$labStatus.MemberServer.Ready
                CheckedAtUtc        = [datetime]::UtcNow.ToString('O')
            }
            $cleanupLedger.Add($cleanupResult)

            Write-Information (
                '[{0:O}] SUITE END {1} result={2} ready={3}' -f
                    [datetime]::UtcNow,
                    $suiteName,
                    $suiteResult.Result,
                    $cleanupResult.Ready
            ) -InformationAction Continue

            if (-not $cleanupResult.Ready) {
                throw [InvalidOperationException]::new(
                    "Suite '$suiteName' left the disposable lab unready."
                )
            }
            if ($suiteResult.Result -ne 'Passed') {
                throw [InvalidOperationException]::new(
                    "Suite '$suiteName' completed with result '$($suiteResult.Result)'."
                )
            }
            if ($suiteResult.TotalCount -le 0 -or
                $suiteResult.PassedCount -le 0) {
                throw [InvalidOperationException]::new(
                    "Suite '$suiteName' executed no passing tests."
                )
            }
            if ($suiteResult.SkippedCount -gt 0) {
                throw [InvalidOperationException]::new(
                    "Suite '$suiteName' reported $($suiteResult.SkippedCount) skipped test(s); exact sanitized reasons were retained."
                )
            }
        }
    }
    catch {
        $terminalError = $_
    }
    finally {
        if ($null -eq $previousMemberServer) {
            Remove-Item Env:WAC_DOMAIN_LAB_MEMBER -ErrorAction SilentlyContinue
        }
        else {
            $env:WAC_DOMAIN_LAB_MEMBER = $previousMemberServer
        }

        $summary = [pscustomobject]@{
            Format             = 'WindowsAccessControl.DomainLabAcceptance'
            SchemaVersion      = 1
            StartedAtUtc       = $startedAtUtc.ToString('O')
            CompletedAtUtc     = [datetime]::UtcNow.ToString('O')
            Result             = if ($terminalError) { 'Failed' } else { 'Passed' }
            CredentialHandling = 'SuiteEphemeralRuntime'
            Suites             = $suiteResults.ToArray()
            CleanupLedger      = $cleanupLedger.ToArray()
        }
        try {
            & $writeEvidence `
                -Summary $summary `
                -OutputPath $OutputPath `
                -SensitiveValues $sensitiveValues
        }
        catch {
            $secondaryErrors.Add($_.Exception)
        }

        try {
            if (-not (Get-Command `
                    -Name Test-WindowsAccessControlDomainFixture `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue)) {
                Import-Module -Name $harnessModulePath -Force -ErrorAction Stop
            }
        }
        catch {
            $secondaryErrors.Add($_.Exception)
        }
    }

    if ($terminalError) {
        if ($secondaryErrors.Count -gt 0) {
            throw [AggregateException]::new(
                "Domain-lab acceptance failed: $($terminalError.Exception.Message) Secondary finalization failure(s) also occurred.",
                [Exception[]]@($terminalError.Exception) +
                    $secondaryErrors.ToArray()
            )
        }
        throw $terminalError
    }
    if ($secondaryErrors.Count -gt 0) {
        throw [AggregateException]::new(
            'Domain-lab acceptance finalization failed.',
            $secondaryErrors.ToArray()
        )
    }
    $summary
}

Export-ModuleMember -Function @(
    'Get-WindowsAccessControlDomainLabPlan'
    'Initialize-WindowsAccessControlDomainLab'
    'Invoke-WindowsAccessControlDomainLabAcceptance'
    'Test-WindowsAccessControlDomainLab'
    'Remove-WindowsAccessControlDomainLab'
)
