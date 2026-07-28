function ConvertTo-WindowsSmbShareRights {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Rights is the established public enum noun used throughout the module.'
    )]
    [CmdletBinding()]
    [OutputType([WindowsSmbShareRights])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateRange(0, 0xFFFFFFFFL)]
        [long]$AccessMask
    )

    process {
        $unsignedMask = [uint32]$AccessMask
        $signedMask = [BitConverter]::ToInt32(
            [BitConverter]::GetBytes($unsignedMask),
            0
        )
        [WindowsSmbShareRights]$signedMask
    }
}