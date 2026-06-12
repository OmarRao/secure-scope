/*
 * apt_lateral_movement.yar — APT Lateral Movement, Credential Dumping, and Persistence
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect post-exploitation techniques used by APT groups and ransomware
 *   affiliates during the lateral movement phase of an intrusion.
 *   Covers the most common LOTL (Living Off the Land) techniques tracked
 *   under MITRE ATT&CK that appear in Volt Typhoon, APT29, Lazarus, and
 *   Scattered Spider intrusions.
 *
 * Coverage:
 *   - LSASS credential dumping (Mimikatz, comsvcs, Task Manager dump)
 *   - Pass-the-Hash / Pass-the-Ticket patterns
 *   - Scheduled task and service persistence
 *   - Active Directory reconnaissance
 *   - Lateral movement via SMB and WMI
 *   - Privilege escalation patterns
 *
 * Note: String patterns are realistic indicators but may produce false positives
 *   in penetration testing toolkits. Evaluate context before alerting.
 *
 * References:
 *   MITRE ATT&CK T1003 — OS Credential Dumping
 *   MITRE ATT&CK T1021 — Remote Services
 *   MITRE ATT&CK T1053 — Scheduled Task/Job
 *   MITRE ATT&CK T1059 — Command and Scripting Interpreter
 */

rule APT_Mimikatz_Patterns
{
    /*
     * Detects Mimikatz credential theft tool patterns.
     * Mimikatz is the most widely used credential dumping tool across
     * ransomware groups, APT actors, and red teams.
     * Covers sekurlsa, kerberos, and lsadump modules.
     */
    meta:
        description    = "Detects Mimikatz credential dumping patterns (sekurlsa, kerberos modules)"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Mimikatz"
        mitre_attack   = "T1003.001"
        created        = "2024-01-01"

    strings:
        /* Mimikatz module names */
        $sekurlsa       = "sekurlsa::" nocase
        $kerberos_mod   = "kerberos::" nocase
        $lsadump        = "lsadump::" nocase
        $privilege_mod  = "privilege::" nocase

        /* Mimikatz command patterns */
        $sekurlsa_logon = "sekurlsa::logonpasswords" nocase
        $sekurlsa_wdigest = "sekurlsa::wdigest" nocase
        $kerberos_ptt   = "kerberos::ptt" nocase
        $dcsync         = "lsadump::dcsync" nocase

        /* Mimikatz banner and version strings */
        $banner         = "mimikatz" nocase
        $banner2        = "gentilkiwi" nocase
        $banner3        = "Benjamin DELPY" nocase

        /* Obfuscated Mimikatz invocations */
        $invoke_mimi    = "Invoke-Mimikatz" nocase
        $invoke_mimi2   = "Invoke-Mimi" nocase

    condition:
        /* Direct Mimikatz usage */
        $banner or $banner2 or $banner3
        or
        /* Module usage without banner */
        2 of ($sekurlsa, $kerberos_mod, $lsadump, $privilege_mod)
        or
        /* PowerShell variants */
        ($invoke_mimi or $invoke_mimi2)
}


rule APT_LSASS_Dump
{
    /*
     * Detects LSASS process memory dumping techniques that do not
     * require Mimikatz directly — using comsvcs.dll, Task Manager,
     * or custom MiniDump invocations.
     */
    meta:
        description    = "Detects LSASS memory dump techniques via comsvcs.dll, MiniDump"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Credential Dumping"
        mitre_attack   = "T1003.001"
        created        = "2024-01-01"

    strings:
        /* comsvcs.dll MiniDump technique */
        $comsvcs_mini   = "comsvcs.dll" nocase
        $minidump       = "MiniDump" nocase
        $lsass_str      = "lsass" nocase

        /* PowerShell LSASS dump via comsvcs */
        $ps_rundll_dump = "rundll32.exe C:\\windows\\System32\\comsvcs.dll" nocase

        /* procdump targeting LSASS */
        $procdump_lsass = "procdump" nocase
        $procdump_flag  = "-ma lsass" nocase

        /* Task Manager dump (manual) — look for the output file */
        $taskman_dump   = "lsass.dmp" nocase
        $taskman_dump2  = "lsass.exe.dmp" nocase

        /* Sysinternals ProcDump alternative patterns */
        $sqldumper      = "SQLDumper.exe" nocase
        $sqldump_lsass  = "lsass.exe" nocase

    condition:
        /* comsvcs + MiniDump + lsass is the classic technique */
        ($comsvcs_mini and $minidump and $lsass_str)
        or
        /* procdump targeting lsass */
        ($procdump_lsass and $procdump_flag)
        or
        /* LSASS dump file artefacts */
        ($taskman_dump or $taskman_dump2)
}


rule APT_Lateral_Movement_WMI
{
    /*
     * Detects lateral movement via Windows Management Instrumentation (WMI)
     * used extensively by Volt Typhoon and APT29 for stealthy remote execution.
     * WMI is a signed Windows binary — execution blends in with normal activity.
     */
    meta:
        description    = "Detects WMI-based lateral movement and remote command execution"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Lateral Movement"
        mitre_attack   = "T1021.006"
        created        = "2024-01-01"

    strings:
        /* wmic remote execution */
        $wmic_node      = "wmic /node:" nocase
        $wmic_process   = "process call create" nocase

        /* PowerShell WMI lateral movement */
        $ps_wmi_invoke  = "Invoke-WmiMethod" nocase
        $ps_wmi_create  = "Win32_Process" nocase
        $ps_wmi_cim     = "Invoke-CimMethod" nocase

        /* WMI subscription for persistence */
        $wmi_sub        = "__EventFilter" nocase
        $wmi_consumer   = "__EventConsumer" nocase
        $wmi_binding    = "__FilterToConsumerBinding" nocase

        /* WMI over network */
        $wmi_connect    = "ConnectServer" nocase
        $wmi_namespace  = "root\\cimv2" nocase

    condition:
        /* Remote WMI execution */
        ($wmic_node and $wmic_process)
        or
        /* PowerShell WMI lateral movement */
        ($ps_wmi_invoke or $ps_wmi_cim) and $ps_wmi_create
        or
        /* WMI persistence subscription — highly suspicious */
        ($wmi_sub and $wmi_consumer and $wmi_binding)
}


rule APT_Active_Directory_Recon
{
    /*
     * Detects Active Directory reconnaissance commands used to map
     * domain topology, identify high-value targets, and find privileged accounts.
     * Commonly observed in Lazarus, APT29, and Scattered Spider intrusions.
     */
    meta:
        description    = "Detects Active Directory enumeration and domain reconnaissance"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "AD Reconnaissance"
        mitre_attack   = "T1087.002"
        created        = "2024-01-01"

    strings:
        /* net commands for AD enumeration */
        $net_domain_adm = "net group \"Domain Admins\"" nocase
        $net_ent_adm    = "net group \"Enterprise Admins\"" nocase
        $net_user_domain= "net user /domain" nocase
        $net_domain     = "net view /domain" nocase

        /* PowerShell AD enumeration */
        $ps_getaduser   = "Get-ADUser" nocase
        $ps_getadgroup  = "Get-ADGroup" nocase
        $ps_getadcomp   = "Get-ADComputer" nocase
        $ps_getdomctrl  = "Get-ADDomainController" nocase

        /* BloodHound / SharpHound artefacts */
        $bloodhound     = "BloodHound" nocase
        $sharphound     = "SharpHound" nocase
        $collection_all = "-CollectionMethod All" nocase

        /* LDAP queries for AD objects */
        $ldap_query     = "samAccountType=805306368" nocase
        $ldap_admin     = "adminCount=1" nocase

        /* nltest domain trust enumeration */
        $nltest_dclist  = "nltest /dclist:" nocase
        $nltest_domain  = "nltest /domain_trusts" nocase

    condition:
        /* Multiple AD enumeration commands together */
        3 of ($net_*, $ps_getad*)
        or
        /* BloodHound/SharpHound collection is highly specific */
        ($bloodhound or $sharphound or $collection_all)
        or
        /* LDAP recon */
        ($ldap_query or $ldap_admin) and ($nltest_dclist or $nltest_domain)
}


rule APT_Persistence_ScheduledTask
{
    /*
     * Detects scheduled task creation used for persistence by APT groups.
     * Scheduled tasks are a primary persistence mechanism for LockBit, SystemBC,
     * and numerous APT groups. Covers schtasks.exe and PowerShell variants.
     */
    meta:
        description    = "Detects scheduled task creation for malware persistence"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Persistence"
        mitre_attack   = "T1053.005"
        created        = "2024-01-01"

    strings:
        /* schtasks creation with persistence-focused flags */
        $schtask_create = "schtasks /create" nocase
        $schtask_system = "/ru SYSTEM" nocase
        $schtask_onlogon= "/sc ONLOGON" nocase
        $schtask_onstart= "/sc ONSTART" nocase
        $schtask_daily  = "/sc DAILY" nocase

        /* PowerShell scheduled task creation */
        $ps_newtask     = "New-ScheduledTask" nocase
        $ps_registertask= "Register-ScheduledTask" nocase
        $ps_taskaction  = "New-ScheduledTaskAction" nocase

        /* Suspicious task actions: running from temp or user directories */
        $task_temp      = "\\AppData\\Local\\Temp\\" nocase
        $task_public    = "\\Users\\Public\\" nocase

    condition:
        /* schtasks with persistence trigger + system context */
        ($schtask_create) and (1 of ($schtask_system, $schtask_onlogon, $schtask_onstart))
        or
        /* PowerShell task registration */
        ($ps_registertask or $ps_newtask) and $ps_taskaction
        or
        /* Task running from suspicious location */
        ($schtask_create or $ps_registertask) and (1 of ($task_temp, $task_public))
}
