function New-WindowsTaskSchedulerService {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This function creates a local COM client and changes no target state.'
    )]
    [CmdletBinding()]
    [OutputType([object])]
    param()

    New-Object -ComObject 'Schedule.Service'
}