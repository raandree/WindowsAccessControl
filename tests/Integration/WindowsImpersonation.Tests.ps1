BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:userName = 'WacImp' + [guid]::NewGuid().ToString('N').Substring(0, 10)
    $script:innerUserName = 'WacImp' + [guid]::NewGuid().ToString('N').Substring(0, 10)
    $script:passwordText = 'Wac!' + [guid]::NewGuid().ToString('N') + 'aA1'
    $script:password = New-Object -TypeName System.Security.SecureString
    foreach ($character in $script:passwordText.ToCharArray()) {
        $script:password.AppendChar($character)
    }
    $script:password.MakeReadOnly()
    $script:credential = [pscredential]::new(
        ".\$($script:userName)",
        $script:password
    )
    $script:innerCredential = [pscredential]::new(
        ".\$($script:innerUserName)",
        $script:password
    )
    $script:callerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:testUser = New-LocalUser `
        -Name $script:userName `
        -Password $script:password `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -ErrorAction Stop
    $script:innerTestUser = New-LocalUser `
        -Name $script:innerUserName `
        -Password $script:password `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -ErrorAction Stop
}

AfterAll {
    Remove-LocalUser -Name $script:userName -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $script:innerUserName -ErrorAction SilentlyContinue
    if ($script:password) {
        $script:password.Dispose()
    }
    $script:passwordText = $null
    $script:password = $null
    $script:credential = $null
    $script:innerCredential = $null
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Local Windows impersonation' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    It 'Should execute as the supplied identity and restore the caller identity' {
        $insideSid = Invoke-WindowsAccessControl `
            -Credential $script:credential `
            -ScriptBlock { param($ExpectedValue) [pscustomobject]@{
                SID   = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                Value = $ExpectedValue
            } } `
            -ArgumentList 'argument-crossed-scope'

        $insideSid.SID | Should -Be $script:testUser.SID.Value
        $insideSid.Value | Should -Be 'argument-crossed-scope'
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value |
            Should -Be $script:callerSid
    }

    It 'Should restore the outer identity after a nested impersonation scope' {
        $states = Invoke-WindowsAccessControl `
            -Credential $script:credential `
            -ScriptBlock {
                $outerBefore = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $inner = Invoke-WindowsAccessControl -Credential $args[0] -ScriptBlock {
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                }
                [pscustomobject]@{
                    OuterBefore = $outerBefore
                    Inner       = $inner
                    OuterAfter  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                }
            } `
            -ArgumentList $script:innerCredential

        $states.OuterBefore | Should -Be $script:testUser.SID.Value
        $states.Inner | Should -Be $script:innerTestUser.SID.Value
        $states.OuterAfter | Should -Be $script:testUser.SID.Value
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value |
            Should -Be $script:callerSid
    }

    It 'Should restore the caller identity when the impersonated operation throws' {
        {
            Invoke-WindowsAccessControl `
                -Credential $script:credential `
                -ScriptBlock { throw 'Expected live impersonation failure.' }
        } | Should -Throw -ExpectedMessage '*Expected live impersonation failure*'

        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value |
            Should -Be $script:callerSid
    }

    It 'Should fail closed without exposing an invalid password' {
        $invalidPasswordText = $script:passwordText + 'Wrong'
        $invalidPassword = New-Object -TypeName System.Security.SecureString
        foreach ($character in $invalidPasswordText.ToCharArray()) {
            $invalidPassword.AppendChar($character)
        }
        $invalidPassword.MakeReadOnly()
        $invalidCredential = [pscredential]::new(
            ".\$($script:userName)",
            $invalidPassword
        )
        $executionMarker = Join-Path -Path $TestDrive -ChildPath 'invalid-executed.txt'

        try {
            $message = try {
                Invoke-WindowsAccessControl `
                    -Credential $invalidCredential `
                    -ScriptBlock { Set-Content -LiteralPath $args[0] -Value 'executed' } `
                    -ArgumentList $executionMarker
            } catch {
                $_.Exception.Message
            }
        } finally {
            $invalidPassword.Dispose()
        }

        $message | Should -Not -BeNullOrEmpty
        $message | Should -Not -Match ([regex]::Escape($invalidPasswordText))
        Test-Path -LiteralPath $executionMarker | Should -BeFalse
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value |
            Should -Be $script:callerSid
    }
}
