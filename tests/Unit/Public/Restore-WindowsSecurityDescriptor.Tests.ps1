. "$PSScriptRoot\WindowsPortabilityCommandContract.ps1"
$contractParameters = @{
    Name               = 'Restore-WindowsSecurityDescriptor'
    RequiredParameters = @(
        'BackupPath'
        'VerificationCertificate'
        'Server'
        'AllowedBaseDistinguishedName'
        'Credential'
        'TimeoutSeconds'
        'PassThru'
    )
}
Register-WindowsPortabilityCommandContract @contractParameters
