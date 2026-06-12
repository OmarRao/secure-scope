/*
 * lockbit.yar — LockBit 3.0 Ransomware Indicators
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect indicators specific to the LockBit 3.0 (LockBit Black) ransomware family.
 *   LockBit 3.0 was first observed in June 2022 and introduced significant obfuscation,
 *   a built-in bug-bounty programme, and Zcash payment support.
 *
 * Coverage:
 *   - LockBit 3.0 ransom note patterns and naming conventions
 *   - LockBit file marker and mutex patterns
 *   - LockBit network communication patterns
 *   - LockBit anti-analysis / anti-debug techniques
 *
 * Note: IOC values (hashes, domains) are fictional/example data for demonstration.
 *   Do NOT use as real threat intelligence.
 *
 * References:
 *   MITRE ATT&CK T1486 — Data Encrypted for Impact
 *   MITRE ATT&CK T1490 — Inhibit System Recovery
 *   MITRE ATT&CK T1562.001 — Disable or Modify Tools
 */

rule LockBit3_RansomNote
{
    /*
     * Detects the LockBit 3.0 ransom note format.
     * LockBit 3.0 uses a distinctive ransom note filename pattern:
     * [LOCKBIT-<victim_id>]-README.txt and similar variants.
     */
    meta:
        description    = "Detects LockBit 3.0 ransom note content and filename patterns"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "LockBit"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* LockBit 3.0 ransom note header */
        $note_header    = "~~~ LockBit" nocase
        $note_black     = "LockBit Black" nocase

        /* LockBit payment portal references */
        $portal_ref     = "lockbitapt" nocase
        $portal_onion   = ".onion" nocase

        /* LockBit victim ID format — hex string in brackets */
        $victim_id      = /\[LOCKBIT-[A-F0-9]{16}\]/ nocase

        /* LockBit warning phrases */
        $warning_delet  = "Do not rename encrypted files" nocase
        $warning_tools  = "Do not try to decrypt" nocase
        $zcash          = "Zcash" nocase

        /* LockBit 3.0 file extension marker (appended to encrypted files) */
        $ext_lockbit3   = /\.[a-f0-9]{9}/ nocase

    condition:
        /* Note header + at least one other LockBit marker */
        ($note_header or $note_black) and (2 of ($portal_ref, $zcash, $victim_id, $warning_delet))
        or
        /* Victim ID format alone is highly specific */
        $victim_id and (1 of ($portal_*, $warning_*))
}


rule LockBit3_Dropper
{
    /*
     * Detects the LockBit 3.0 dropper/loader based on anti-analysis techniques
     * and obfuscation patterns characteristic of LockBit Black builds.
     * LockBit 3.0 borrows BlackMatter source code components.
     */
    meta:
        description    = "Detects LockBit 3.0 dropper anti-analysis and obfuscation patterns"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "LockBit"
        mitre_attack   = "T1562.001"
        created        = "2024-01-01"

    strings:
        /* Mutex name patterns used by LockBit 3.0 to prevent double encryption */
        $mutex_lb3      = { 47 6C 6F 62 61 6C 5C 4C 6F 63 6B 42 69 74 }  /* "Global\LockBit" */

        /* Anti-debug: IsDebuggerPresent followed by ExitProcess pattern */
        $antidebug      = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF 15 ?? ?? ?? ?? }

        /* LockBit 3.0 custom hash algorithm seed (partial) */
        $hash_seed      = { B8 37 13 00 00 F7 E1 }

        /* Characteristic NOP sled with junk code used in LockBit 3.0 obfuscation */
        $junk_nop       = { 90 90 90 EB ?? 90 90 }

        /* LockBit command line argument for silent mode */
        $silent_arg     = "-silent" nocase
        $pass_arg       = "-pass" nocase

        /* Windows service name used for persistence (example pattern) */
        $svc_name       = "LockBit_Service" nocase

    condition:
        /* Mutex + anti-debug or hash pattern */
        ($mutex_lb3 and ($antidebug or $hash_seed))
        or
        /* Service name + silent mode args */
        ($svc_name and ($silent_arg or $pass_arg))
}


rule LockBit3_DefenceEvasion
{
    /*
     * Detects LockBit 3.0 defence evasion techniques including
     * security tool termination, logging suppression, and firewall modification.
     */
    meta:
        description    = "Detects LockBit 3.0 defence evasion and security tool termination"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "LockBit"
        mitre_attack   = "T1562.001"
        created        = "2024-01-01"

    strings:
        /* Security software process names LockBit terminates */
        $kill_av1       = "MsMpEng.exe" nocase
        $kill_av2       = "ccSvcHst.exe" nocase
        $kill_av3       = "avgnt.exe" nocase
        $kill_edr       = "CarbonBlack" nocase

        /* Windows Defender / security centre disablement */
        $wdef_disable   = "Set-MpPreference -DisableRealtimeMonitoring $true" nocase
        $wdef_disable2  = "sc stop WinDefend" nocase

        /* Event log clearing */
        $evtclear       = "wevtutil cl" nocase
        $evtclear2      = "Clear-EventLog" nocase

        /* Firewall disablement */
        $fw_off         = "netsh advfirewall set allprofiles state off" nocase

    condition:
        /* Multiple defence evasion techniques together */
        (2 of ($kill_*)) or ($wdef_disable or $wdef_disable2) or ($evtclear and $fw_off)
}
