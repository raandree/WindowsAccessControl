function Resolve-WindowsServiceTarget {
    [CmdletBinding(DefaultParameterSetName = 'Service')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Service')]
        [ValidateNotNull()]
        [object]$Name,

        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [switch]$ServiceControlManager
    )

    process {
        if ($ServiceControlManager) {
            return [pscustomobject]@{
                ObjectType       = 'ServiceControlManager'
                Path             = 'SCManager'
                ServiceName      = $null
                NativePath       = $null
                NativeObjectType = [int][WindowsSecurityObjectType]::Service
                DescriptorSource = 'ServiceControlManager'
                CanonicalTarget  = 'ServiceControlManager:Local'
            }
        }

        $serviceControllerType = ([System.Management.Automation.PSTypeName](
            'System.ServiceProcess.ServiceController'
        )).Type
        if (-not $serviceControllerType) {
            foreach ($assemblyName in 'System.ServiceProcess', 'System.ServiceProcess.ServiceController') {
                try {
                    Add-Type -AssemblyName $assemblyName -ErrorAction Stop
                    $serviceControllerType = ([System.Management.Automation.PSTypeName](
                        'System.ServiceProcess.ServiceController'
                    )).Type
                    if ($serviceControllerType) { break }
                } catch {
                    continue
                }
            }
        }

        $serviceName = if ($serviceControllerType -and
            $serviceControllerType.IsInstanceOfType($Name)) {
            $machineName = [string]$Name.MachineName
            if ($machineName -notin @('.', 'localhost', $env:COMPUTERNAME)) {
                throw [System.NotSupportedException]::new(
                    "Remote ServiceController objects are not supported: '$machineName'."
                )
            }
            $Name.ServiceName
        } elseif ($Name.PSObject.Properties['ServiceName']) {
            if ($Name.PSObject.Properties['MachineName']) {
                $machineName = [string]$Name.MachineName
                if ($machineName -notin @('.', 'localhost', $env:COMPUTERNAME)) {
                    throw [System.NotSupportedException]::new(
                        "Remote service targets are not supported: '$machineName'."
                    )
                }
            }
            [string]$Name.ServiceName
        } else {
            [string]$Name
        }
        if ([string]::IsNullOrWhiteSpace($serviceName)) {
            throw [System.ArgumentException]::new('A service name is required.')
        }
        if ($serviceName -match '[\\/]') {
            throw [System.NotSupportedException]::new(
                "Remote or qualified service targets are not supported: '$serviceName'."
            )
        }

        [pscustomobject]@{
            ObjectType       = 'Service'
            Path             = $serviceName
            ServiceName      = $serviceName
            NativePath       = $serviceName
            NativeObjectType = [int][WindowsSecurityObjectType]::Service
            DescriptorSource = 'Named'
            CanonicalTarget  = 'Service:{0}' -f $serviceName.ToUpperInvariant()
        }
    }
}
