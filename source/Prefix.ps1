if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw [System.PlatformNotSupportedException]::new(
        'WindowsAccessControl manages Windows NTFS security descriptors and is supported only on Windows.'
    )
}