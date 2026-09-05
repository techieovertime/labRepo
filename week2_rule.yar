rule Week2_Sample_sample1_native
{
    meta:
        author = "SL-001118623"
        date = "9/6/2026"
        description = "Detects sample1_native.exe - training sample with persistence, C2 URL, and API-based evasion indicators"
        sample_hash = "7350e0cb8b84c828f0674d43efa9b7e6d22e8f3673c41237fb1d6bde2b920e43"

    strings:
        // Network IOC
        $url1 = "http://malicious-domain.com/login.php"

        // Persistence (registry)
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg2 = "SYSTEM\\CurrentControlSet\\Services"

        // Suspicious file path
        $path1 = "AppData\\Roaming\\svchost.exe"

        // Suspicious/evasive APIs
        $api1 = "CreateProcessA"
        $api2 = "VirtualProtect"
        $api3 = "GetLastError"
        $api4 = "DeleteCriticalSection"

    condition:
        uint16(0) == 0x5A4D and  // MZ header check, confirms it's a PE
        3 of them
}
