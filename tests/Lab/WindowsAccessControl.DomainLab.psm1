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

function Get-WindowsAccessControlLabCoveragePlan {
    <#
        .SYNOPSIS
            Reads the measurable code locations published by the acceptance
            runner for the current lab run.

        .DESCRIPTION
            The acceptance runner owns the coverage session. It publishes the
            measurable locations of the module under test into the directory
            named by WAC_DOMAIN_LAB_COVERAGE so that suites which execute the
            module in a remote session can arm the same locations there. The
            plan is absent when a suite runs outside the acceptance profile, in
            which case remote coverage is skipped rather than failing the suite.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ([string]::IsNullOrWhiteSpace($env:WAC_DOMAIN_LAB_COVERAGE)) {
        return $null
    }

    $planPath = Join-Path -Path $env:WAC_DOMAIN_LAB_COVERAGE -ChildPath 'breakpoints.json'
    if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
        return $null
    }

    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    if ([int]$plan.SchemaVersion -ne 1) {
        throw [InvalidOperationException]::new(
            "Unsupported domain-lab coverage plan version: '$($plan.SchemaVersion)'."
        )
    }

    [pscustomobject]@{
        Directory  = $env:WAC_DOMAIN_LAB_COVERAGE
        ModuleHash = [string]$plan.ModuleHash
        Lines      = [int[]]$plan.Lines
        Columns    = [int[]]$plan.Columns
    }
}

function Enter-WindowsAccessControlMemberCoverage {
    <#
        .SYNOPSIS
            Arms code-coverage collection for the module copy that a suite
            drives inside a member-server session.

        .DESCRIPTION
            Code coverage instruments the runspace that executes the code, so a
            suite whose real work runs through Invoke-Command against the member
            server records nothing on the harness side. This arms the same
            measurable locations in the member runspace, keyed by position in the
            plan the acceptance runner published, and refuses to arm a module
            file whose content differs from the measured one.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidGlobalVars',
        '',
        Justification = 'The armed breakpoints must outlive the remote scriptblock that sets them.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseUsingScopeModifierInNewRunspaces',
        '',
        Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
    )]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ModulePath
    )

    $plan = Get-WindowsAccessControlLabCoveragePlan
    if ($null -eq $plan) {
        return 0
    }

    [int](Invoke-Command `
        -Session $Session `
        -ArgumentList $ModulePath, $plan.Lines, $plan.Columns, $plan.ModuleHash `
        -ErrorAction Stop `
        -ScriptBlock {
            param($ModulePath, $Lines, $Columns, $ModuleHash)

            $ErrorActionPreference = 'Stop'
            $algorithm = [Security.Cryptography.SHA256]::Create()
            try {
                $stream = [IO.File]::OpenRead($ModulePath)
                try {
                    $actualHash = [BitConverter]::ToString(
                        $algorithm.ComputeHash($stream)
                    ).Replace('-', '')
                }
                finally {
                    $stream.Dispose()
                }
            }
            finally {
                $algorithm.Dispose()
            }
            if ($actualHash -cne $ModuleHash) {
                throw [InvalidOperationException]::new(
                    'The member module under test does not match the measured module.'
                )
            }

            $action = { $null = Remove-PSBreakpoint -Id $_.Id }
            $global:WindowsAccessControlCoverageBreakpoints = @(
                for ($index = 0; $index -lt $Lines.Count; $index++) {
                    Set-PSBreakpoint `
                        -Script $ModulePath `
                        -Line $Lines[$index] `
                        -Column $Columns[$index] `
                        -Action $action
                }
            )
            @($global:WindowsAccessControlCoverageBreakpoints).Count
        })
}

function Exit-WindowsAccessControlMemberCoverage {
    <#
        .SYNOPSIS
            Harvests the member-runspace coverage hits of one suite and retains
            them for the acceptance runner.

        .DESCRIPTION
            Hit counts are returned in plan order so the runner can add them to
            the locations it measured on the harness side. A count that does not
            match the plan is refused rather than attributed to the wrong
            locations.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidGlobalVars',
        '',
        Justification = 'The armed breakpoints outlive the remote scriptblock that set them.'
    )]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $plan = Get-WindowsAccessControlLabCoveragePlan
    if ($null -eq $plan) {
        return 0
    }

    $hitCounts = [int[]]@(Invoke-Command `
        -Session $Session `
        -ErrorAction Stop `
        -ScriptBlock {
            $breakpoints = @($global:WindowsAccessControlCoverageBreakpoints)
            Remove-Variable `
                -Name 'WindowsAccessControlCoverageBreakpoints' `
                -Scope Global `
                -ErrorAction SilentlyContinue
            $unhit = @($breakpoints | Where-Object { $_.HitCount -eq 0 })
            if ($unhit.Count -gt 0) {
                Remove-PSBreakpoint -Breakpoint $unhit -ErrorAction SilentlyContinue
            }
            $breakpoints | ForEach-Object { [int]$_.HitCount }
        })

    if ($hitCounts.Count -ne $plan.Lines.Count) {
        throw [InvalidOperationException]::new(
            ("Suite '$Name' returned $($hitCounts.Count) member coverage counts " +
                "but the plan measures $($plan.Lines.Count) locations.")
        )
    }

    $hitsPath = Join-Path -Path $plan.Directory -ChildPath (
        'hits-{0}.json' -f [IO.Path]::GetFileNameWithoutExtension($Name)
    )
    [IO.File]::WriteAllText(
        $hitsPath,
        ([pscustomobject]@{
            SchemaVersion = 1
            Suite         = $Name
            HitCounts     = $hitCounts
        } | ConvertTo-Json -Depth 4 -Compress),
        [Text.UTF8Encoding]::new($false)
    )

    @($hitCounts | Where-Object { $_ -gt 0 }).Count
}

function Get-WindowsAccessControlLabPesterModule {
    [CmdletBinding()]
    [OutputType([psmoduleinfo])]
    param()

    $pesterModule = @(
        Get-Module -Name 'Pester' |
            Where-Object { $_.Version -ge [version]'5.7.1' } |
            Sort-Object -Property Version -Descending
    ) | Select-Object -First 1
    if ($null -eq $pesterModule) {
        Import-Module -Name 'Pester' -MinimumVersion 5.7.1 -ErrorAction Stop
        $pesterModule = @(
            Get-Module -Name 'Pester' |
                Where-Object { $_.Version -ge [version]'5.7.1' } |
                Sort-Object -Property Version -Descending
        ) | Select-Object -First 1
    }
    if ($null -eq $pesterModule) {
        throw [InvalidOperationException]::new(
            'Code coverage requires Pester 5.7.1 or later in the lab session.'
        )
    }

    $pesterModule
}

function Enter-WindowsAccessControlLabCoverage {
    <#
        .SYNOPSIS
            Starts the acceptance-wide code-coverage session over the built
            module the lab runs.

        .DESCRIPTION
            Coverage is accumulated once for the whole acceptance rather than
            once per suite, so a single JaCoCo document covers every family.
            This discovers the measurable locations without instrumenting
            anything: the harness side is measured by Pester itself while each
            suite runs, and the same locations are published for the suites that
            execute the module in a member-server session.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The public acceptance runner enforces ShouldProcess before starting coverage.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$ModulePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkingDirectory
    )

    $pesterModule = Get-WindowsAccessControlLabPesterModule
    $resolvedModulePath = (Resolve-Path -LiteralPath $ModulePath).ProviderPath
    $breakpoints = @(& $pesterModule {
            param($Path)

            Set-StrictMode -Off
            Enter-CoverageAnalysis -CodeCoverage $Path -UseBreakpoints $false
        } $resolvedModulePath)
    if ($breakpoints.Count -eq 0) {
        throw [InvalidOperationException]::new(
            "No measurable code locations were found in '$resolvedModulePath'."
        )
    }

    $positionIndex = @{ }
    for ($index = 0; $index -lt $breakpoints.Count; $index++) {
        $key = '{0}:{1}' -f $breakpoints[$index].StartLine, $breakpoints[$index].StartColumn
        if (-not $positionIndex.ContainsKey($key)) {
            $positionIndex[$key] = $index
        }
    }

    $null = New-Item -Path $WorkingDirectory -ItemType Directory -Force
    Get-ChildItem -LiteralPath $WorkingDirectory -Filter 'hits-*.json' -File |
        Remove-Item -Force -ErrorAction Stop

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($resolvedModulePath)
        try {
            $moduleHash = [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '')
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $algorithm.Dispose()
    }

    $plan = [pscustomobject]@{
        SchemaVersion = 1
        ModuleHash    = $moduleHash
        Lines         = [int[]]@($breakpoints | ForEach-Object { [int]$_.StartLine })
        Columns       = [int[]]@($breakpoints | ForEach-Object { [int]$_.StartColumn })
    }
    [IO.File]::WriteAllText(
        (Join-Path -Path $WorkingDirectory -ChildPath 'breakpoints.json'),
        ($plan | ConvertTo-Json -Depth 4 -Compress),
        [Text.UTF8Encoding]::new($false)
    )

    $previousDirectory = $env:WAC_DOMAIN_LAB_COVERAGE
    $env:WAC_DOMAIN_LAB_COVERAGE = $WorkingDirectory

    [pscustomobject]@{
        Breakpoints       = $breakpoints
        PositionIndex     = $positionIndex
        HarnessHits       = [int[]]::new($breakpoints.Count)
        Directory         = $WorkingDirectory
        ModulePath        = $resolvedModulePath
        PesterModule      = $pesterModule
        StartedAtUtc      = [datetime]::UtcNow
        PreviousDirectory = $previousDirectory
    }
}

function Add-WindowsAccessControlLabCoverageHit {
    <#
        .SYNOPSIS
            Accumulates the commands one suite executed in the harness runspace.

        .DESCRIPTION
            Pester measures each suite with its own tracer-based coverage run.
            Breakpoints are not used on this side: their per-hit action adds
            call frames, and the directory suites already sit close to the
            call-depth budget of the runspace that runs them.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The public acceptance runner enforces ShouldProcess before collecting coverage.'
    )]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$CoverageSession,

        [Parameter(Mandatory)]
        [object]$PesterResult
    )

    $executed = @($PesterResult.CodeCoverage.CommandsExecuted)
    foreach ($command in $executed) {
        $key = '{0}:{1}' -f $command.StartLine, $command.StartColumn
        if (-not $CoverageSession.PositionIndex.ContainsKey($key)) {
            throw [InvalidOperationException]::new(
                "Pester reported a covered location the session does not measure: '$key'."
            )
        }
        $position = $CoverageSession.PositionIndex[$key]
        $CoverageSession.HarnessHits[$position] += [math]::Max(1, [int]$command.HitCount)
    }

    $executed.Count
}

function Exit-WindowsAccessControlLabCoverage {
    <#
        .SYNOPSIS
            Closes the acceptance-wide coverage session and writes one JaCoCo
            document that combines harness-side and member-session hits.

        .DESCRIPTION
            The document is generated from the harness-side locations, so every
            class, method, and source-file name is relative to the built module
            directory and matches the document the repository build produces for
            the same version. Member-session hits are added by plan position.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The public acceptance runner enforces ShouldProcess before writing coverage.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$CoverageSession,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    $breakpoints = @($CoverageSession.Breakpoints)
    $harnessHits = [int[]]$CoverageSession.HarnessHits

    $memberHits = [int[]]::new($harnessHits.Count)
    $suiteNames = [Collections.Generic.List[string]]::new()
    foreach ($hitsFile in @(
            Get-ChildItem -LiteralPath $CoverageSession.Directory -Filter 'hits-*.json' -File |
                Sort-Object -Property Name
        )) {
        $hits = Get-Content -LiteralPath $hitsFile.FullName -Raw | ConvertFrom-Json
        $counts = [int[]]$hits.HitCounts
        if ($counts.Count -ne $harnessHits.Count) {
            throw [InvalidOperationException]::new(
                ("Member coverage file '$($hitsFile.Name)' reports $($counts.Count) " +
                    "locations but the session measures $($harnessHits.Count).")
            )
        }
        for ($index = 0; $index -lt $counts.Count; $index++) {
            $memberHits[$index] += $counts[$index]
        }
        $suiteNames.Add([string]$hits.Suite)
    }

    $memberOnly = 0
    for ($index = 0; $index -lt $breakpoints.Count; $index++) {
        if ($harnessHits[$index] -eq 0 -and $memberHits[$index] -gt 0) {
            $memberOnly++
        }
        $breakpoints[$index].Breakpoint = @{
            HitCount = $harnessHits[$index] + $memberHits[$index]
        }
    }

    $elapsed = [long][math]::Max(
        1,
        ([datetime]::UtcNow - $CoverageSession.StartedAtUtc).TotalMilliseconds
    )
    $report = & $CoverageSession.PesterModule {
        param($Coverage)

        Set-StrictMode -Off
        Get-CoverageReport -CommandCoverage $Coverage
    } $breakpoints
    $documentXml = & $CoverageSession.PesterModule {
        param($Coverage, $Report, $Milliseconds)

        Set-StrictMode -Off
        Get-JaCoCoReportXml `
            -CommandCoverage $Coverage `
            -CoverageReport $Report `
            -TotalMilliseconds $Milliseconds `
            -Format 'JaCoCo'
    } $breakpoints $report $elapsed
    if ([string]::IsNullOrWhiteSpace($documentXml)) {
        throw [InvalidOperationException]::new(
            'The domain-lab coverage session produced no JaCoCo document.'
        )
    }

    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($OutputPath),
        $documentXml,
        [Text.Encoding]::ASCII
    )

    if ($null -eq $CoverageSession.PreviousDirectory) {
        Remove-Item Env:WAC_DOMAIN_LAB_COVERAGE -ErrorAction SilentlyContinue
    }
    else {
        $env:WAC_DOMAIN_LAB_COVERAGE = $CoverageSession.PreviousDirectory
    }

    [pscustomobject]@{
        CommandsAnalyzed   = [int]$report.NumberOfCommandsAnalyzed
        CommandsExecuted   = [int]$report.NumberOfCommandsExecuted
        CoveragePercent    = [math]::Round([double]$report.CoveragePercent, 2)
        HarnessCommands    = @($harnessHits | Where-Object { $_ -gt 0 }).Count
        MemberCommands     = @($memberHits | Where-Object { $_ -gt 0 }).Count
        MemberOnlyCommands = $memberOnly
        MemberSuites       = $suiteNames.ToArray()
    }
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
        [string]$OutputPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CoverageOutputPath
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
    $builtModulePath = $null
    if ($PSBoundParameters.ContainsKey('CoverageOutputPath')) {
        $builtModule = @(
            Get-ChildItem -Path (
                Join-Path $repositoryPath 'output\module\WindowsAccessControl\*'
            ) -Directory -ErrorAction Stop |
                Sort-Object -Property { [version]$_.Name } -Descending
        ) | Select-Object -First 1
        if ($null -eq $builtModule) {
            throw [IO.DirectoryNotFoundException]::new(
                'RepositoryRoot does not contain a built module to measure.'
            )
        }
        $builtModulePath = Join-Path $builtModule.FullName 'WindowsAccessControl.psm1'
        if (-not (Test-Path -LiteralPath $builtModulePath -PathType Leaf)) {
            throw [IO.FileNotFoundException]::new(
                "The built module to measure does not exist: '$builtModulePath'."
            )
        }
    }
    $suiteNames = @(
        'WindowsAccessControl.DomainLab.Live.Tests.ps1'
        'CertificatePrivateKeyPermissions.Live.Tests.ps1'
        'TaskSchedulerPermissions.Live.Tests.ps1'
        'SmbSharePermissions.Live.Tests.ps1'
        'ADObjectPermissions.Live.Tests.ps1'
        'ADObjectReplication.Live.Tests.ps1'
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
    $addCoverageHit = (Get-Command `
        -Name Add-WindowsAccessControlLabCoverageHit `
        -CommandType Function `
        -ErrorAction Stop).ScriptBlock
    $exitCoverage = (Get-Command `
        -Name Exit-WindowsAccessControlLabCoverage `
        -CommandType Function `
        -ErrorAction Stop).ScriptBlock
    $startedAtUtc = [datetime]::UtcNow
    $suiteResults = [Collections.Generic.List[object]]::new()
    $cleanupLedger = [Collections.Generic.List[object]]::new()
    $previousMemberServer = $env:WAC_DOMAIN_LAB_MEMBER
    $coverageSession = $null
    $coverage = $null
    $summary = $null
    $terminalError = $null
    $secondaryErrors = [Collections.Generic.List[Exception]]::new()
    try {
        $env:WAC_DOMAIN_LAB_MEMBER = $MemberServer
        if ($null -ne $builtModulePath) {
            $coverageSession = Enter-WindowsAccessControlLabCoverage `
                -ModulePath $builtModulePath `
                -WorkingDirectory (Join-Path `
                    ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($CoverageOutputPath))) `
                    'lab-coverage')
            Write-Information (
                '[{0:O}] COVERAGE START locations={1}' -f
                    [datetime]::UtcNow,
                    @($coverageSession.Breakpoints).Count
            ) -InformationAction Continue
        }
        foreach ($suitePath in $suitePaths) {
            $suiteName = [IO.Path]::GetFileName($suitePath)
            $suiteStartedAtUtc = [datetime]::UtcNow
            Write-Information (
                '[{0:O}] SUITE START {1}' -f $suiteStartedAtUtc, $suiteName
            ) -InformationAction Continue

            $pesterResult = if ($null -eq $coverageSession) {
                Invoke-Pester `
                    -Path $suitePath `
                    -Output Detailed `
                    -PassThru
            }
            else {
                $suiteConfiguration = New-PesterConfiguration
                $suiteConfiguration.Run.Path = $suitePath
                $suiteConfiguration.Run.PassThru = $true
                $suiteConfiguration.Output.Verbosity = 'Detailed'
                $suiteConfiguration.CodeCoverage.Enabled = $true
                $suiteConfiguration.CodeCoverage.Path = $coverageSession.ModulePath
                $suiteConfiguration.CodeCoverage.UseBreakpoints = $false
                $suiteConfiguration.CodeCoverage.OutputPath = Join-Path `
                    $coverageSession.Directory `
                    ('suite-{0}.xml' -f [IO.Path]::GetFileNameWithoutExtension($suiteName))
                Invoke-Pester -Configuration $suiteConfiguration
            }
            if ($null -ne $coverageSession) {
                $null = & $addCoverageHit `
                    -CoverageSession $coverageSession `
                    -PesterResult $pesterResult
            }
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

        if ($null -ne $coverageSession) {
            try {
                $coverage = & $exitCoverage `
                    -CoverageSession $coverageSession `
                    -OutputPath $CoverageOutputPath
                Write-Information (
                    '[{0:O}] COVERAGE WRITTEN analyzed={1} executed={2} percent={3} member-only={4}' -f
                        [datetime]::UtcNow,
                        $coverage.CommandsAnalyzed,
                        $coverage.CommandsExecuted,
                        $coverage.CoveragePercent,
                        $coverage.MemberOnlyCommands
                ) -InformationAction Continue
            }
            catch {
                $secondaryErrors.Add($_.Exception)
            }
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
            CodeCoverage       = $coverage
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
    'Enter-WindowsAccessControlMemberCoverage'
    'Exit-WindowsAccessControlMemberCoverage'
)
