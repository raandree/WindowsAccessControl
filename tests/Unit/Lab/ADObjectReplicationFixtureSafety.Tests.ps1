BeforeAll {
    $fixturePath = Join-Path $PSScriptRoot '..\..\Lab\ADObjectReplication.Live.Tests.ps1'
    $parseErrors = $null
    $tokens = $null
    $fixtureAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $fixturePath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw 'The replication integration fixture could not be parsed.'
    }
    $fixtureCase = $fixtureAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'It' -and
            $node.CommandElements[1].Value -eq
                'Should reject an old expected GUID after a distinguished name is reused'
    }, $true)
    $script:fixtureTest = $fixtureCase.CommandElements[-1].ScriptBlock.GetScriptBlock()

    function script:New-DisposableOrganizationalUnit {
        param([string]$Name)

        $distinguishedName = "OU=$Name,$script:targetOu"
        $script:createdOrganizationalUnits.Add($distinguishedName)
        $distinguishedName
    }

    function Get-ADObjectSecurityDescriptor {
        [CmdletBinding()]
        param($Server, $DistinguishedName, $ThrottleLimit)

        throw "Unexpected descriptor read: $Server, $DistinguishedName, $ThrottleLimit."
    }

    function Set-ADObjectSecurityDescriptor {
        [CmdletBinding(SupportsShouldProcess)]
        param($Server, $DistinguishedName, $ExpectedObjectGuid, $AllowedBaseDistinguishedName, $Sddl, $ThrottleLimit)

        if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Mock-only descriptor mutation')) {
            throw "Unexpected descriptor write: $Server, $ExpectedObjectGuid, $AllowedBaseDistinguishedName, $Sddl, $ThrottleLimit."
        }
    }

    function New-ADOrganizationalUnit {
        [CmdletBinding(SupportsShouldProcess)]
        param($Name, $Path, $Server, $ProtectedFromAccidentalDeletion, [switch]$PassThru)

        if ($PSCmdlet.ShouldProcess("OU=$Name,$Path", 'Mock-only OU creation')) {
            throw "Unexpected OU creation: $Server, $ProtectedFromAccidentalDeletion, $PassThru."
        }
    }

    function Remove-ADOrganizationalUnit {
        [CmdletBinding(SupportsShouldProcess)]
        param($Identity, $Server)

        if ($PSCmdlet.ShouldProcess($Identity, 'Mock-only OU deletion')) {
            throw "Unexpected OU deletion on $Server."
        }
    }
}

Describe 'Replication GUID-reuse fixture ownership' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:primaryServer = 'dc1.example.test'
        $script:targetOu = 'OU=Targets,DC=example,DC=test'
        $script:createdOrganizationalUnits = [Collections.Generic.List[string]]::new()
        $script:originalGuid = [guid]'27cb40c6-3f6d-45bc-a4b0-ab71beb01f13'
        $script:replacementGuid = [guid]'6c8195f0-5da3-4b12-bcc2-bb954eb504bc'
        $script:replacementCreated = $false
        Mock Get-ADObjectSecurityDescriptor {
            [pscustomobject]@{
                ObjectGuid = if ($script:replacementCreated) { $script:replacementGuid } else { $script:originalGuid }
                Sddl = 'D:(A;;RP;;;WD)'
            }
        }
        Mock Remove-ADOrganizationalUnit { }
        Mock New-ADOrganizationalUnit {
            $script:replacementCreated = $true
            [pscustomobject]@{
                DistinguishedName = "OU=$Name,$Path"
                ObjectGuid = $script:replacementGuid
            }
        }
        Mock Set-ADObjectSecurityDescriptor { throw 'The object GUID no longer matches.' }
    }

    It 'Should release the obsolete cleanup entry after deleting both object identities' {
        & $script:fixtureTest

        $script:createdOrganizationalUnits.Count | Should -Be 0
        Should -Invoke Remove-ADOrganizationalUnit -Exactly -Times 1 -ParameterFilter {
            $Identity -eq $script:originalGuid
        }
        Should -Invoke Remove-ADOrganizationalUnit -Exactly -Times 1 -ParameterFilter {
            $Identity -eq $script:replacementGuid
        }
    }

    It 'Should keep the original cleanup entry when its deletion fails' {
        Mock Remove-ADOrganizationalUnit { throw 'Expected original deletion failure.' } -ParameterFilter {
            $Identity -eq $script:originalGuid
        }

        { & $script:fixtureTest } | Should -Throw '*Expected original deletion failure*'

        $script:createdOrganizationalUnits | Should -Contain "OU=WacReplExpectedGuid,$script:targetOu"
        Should -Invoke New-ADOrganizationalUnit -Exactly -Times 0
    }

    It 'Should not retain an absent identity when creating its replacement fails' {
        Mock New-ADOrganizationalUnit { throw 'Expected replacement creation failure.' }

        { & $script:fixtureTest } | Should -Throw '*Expected replacement creation failure*'

        $script:createdOrganizationalUnits.Count | Should -Be 0
        Should -Invoke Remove-ADOrganizationalUnit -Exactly -Times 1 -ParameterFilter {
            $Identity -eq $script:originalGuid
        }
    }
}
