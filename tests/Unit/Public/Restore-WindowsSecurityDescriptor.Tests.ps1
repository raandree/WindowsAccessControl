. "$PSScriptRoot\WindowsPortabilityCommandContract.ps1"
$contractParameters = @{
    Name               = 'Restore-WindowsSecurityDescriptor'
    RequiredParameters = @(
        'BackupPath'
        'VerificationCertificate'
        'PassThru'
    )
}
Register-WindowsPortabilityCommandContract @contractParameters
