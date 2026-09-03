BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:password = New-Object -TypeName System.Security.SecureString
    foreach ($character in 'not-a-real-password'.ToCharArray()) {
        $script:password.AppendChar($character)
    }
    $script:password.MakeReadOnly()
    $script:credential = [pscredential]::new(
        '.\WacImpersonationTest',
        $script:password
    )
}

AfterAll {
    $script:password.Dispose()
    $script:password = $null
    $script:credential = $null
}

Describe 'Invoke-WindowsAccessControl' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-WithWindowsImpersonation -MockWith {
            & $ScriptBlock @ArgumentList
        }
    }

    It 'Should execute the script block with its arguments under the supplied credential scope' {
        $result = Invoke-WindowsAccessControl `
            -Credential $script:credential `
            -ScriptBlock { param($Left, $Right) "$Left-$Right" } `
            -ArgumentList 'one', 'two'

        $result | Should -Be 'one-two'
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-WithWindowsImpersonation `
            -Times 1 `
            -Exactly `
            -ParameterFilter { $Credential.UserName -eq '.\WacImpersonationTest' }
    }

    It 'Should preserve a terminating error from the impersonated operation' {
        {
            Invoke-WindowsAccessControl `
                -Credential $script:credential `
                -ScriptBlock { throw 'Expected impersonated failure.' }
        } | Should -Throw -ExpectedMessage '*Expected impersonated failure*'
    }

    It 'Should not include the credential password in an impersonation failure' {
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-WithWindowsImpersonation -MockWith {
            throw "Logon failed for $($Credential.UserName)."
        }

        $message = try {
            Invoke-WindowsAccessControl `
                -Credential $script:credential `
                -ScriptBlock { 'not reached' }
        } catch {
            $_.Exception.Message
        }

        $message | Should -Be 'Logon failed for .\WacImpersonationTest.'
        $message | Should -Not -Match 'not-a-real-password'
    }
}
