. "$PSScriptRoot\WindowsPortabilityCommandContract.ps1"
$contractParameters = @{
    Name               = 'Backup-WindowsSecurityDescriptor'
    RequiredParameters = @(
        'InputObject'
        'DestinationPath'
        'SigningCertificate'
        'Force'
        'PassThru'
    )
}
Register-WindowsPortabilityCommandContract @contractParameters
