/*
 * blackcat_alphv.yar — BlackCat / ALPHV Ransomware Indicators
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect indicators specific to the BlackCat (ALPHV) ransomware family.
 *   BlackCat was the first major ransomware written in Rust, making it
 *   highly portable (Windows, Linux, VMware ESXi) and harder to reverse-engineer
 *   than traditional C/C++ ransomware.
 *
 * Coverage:
 *   - BlackCat Rust binary markers and compiler artefacts
 *   - BlackCat configuration JSON schema patterns
 *   - BlackCat ransom note and file marker patterns
 *   - BlackCat ESXi targeting commands
 *   - ALPHV affiliate panel communication patterns
 *
 * Note: IOC values are fictional/example data for demonstration only.
 *
 * References:
 *   MITRE ATT&CK T1486 — Data Encrypted for Impact
 *   MITRE ATT&CK T1059.004 — Unix Shell
 *   MITRE ATT&CK T1070.004 — File Deletion
 */

rule BlackCat_RustBinary
{
    /*
     * Detects BlackCat Rust binary markers.
     * Rust binaries include characteristic metadata strings and panic handler
     * references that can identify them even without symbols.
     * BlackCat also embeds its configuration JSON inside the binary.
     */
    meta:
        description    = "Detects BlackCat/ALPHV Rust binary characteristics and embedded config markers"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "BlackCat"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* Rust panic handler — present in all Rust binaries */
        $rust_panic     = "panicked at" nocase
        $rust_core      = "rust_begin_unwind" nocase

        /* BlackCat configuration JSON keys embedded in binary */
        $cfg_key1       = "\"extension\":" nocase
        $cfg_key2       = "\"note_file_name\":" nocase
        $cfg_key3       = "\"note_full_text\":" nocase
        $cfg_key4       = "\"default_file_mode\":" nocase
        $cfg_key5       = "\"credentials\":" nocase

        /* BlackCat access token pattern (used for affiliate tracking) */
        $access_token   = "\"access_token\":" nocase

        /* BlackCat network communication strings */
        $alphv_url      = "alphvmmm27o3ycmjoin3implfl5ff3f6a7jzogp3en7f7xxrwsuni4yd" nocase

        /* BlackCat self-propagation via PsExec */
        $psexec_spread  = "psexec" nocase

    condition:
        /* Rust binary markers + BlackCat config keys */
        ($rust_panic or $rust_core) and (3 of ($cfg_key*))
        or
        /* Access token + config structure */
        ($access_token and 2 of ($cfg_key*))
}


rule BlackCat_RansomNote
{
    /*
     * Detects BlackCat/ALPHV ransom note content and naming.
     * BlackCat uses a configurable ransom note name stored in its JSON config,
     * commonly RECOVER-<ext>-FILES.txt or similar patterns.
     */
    meta:
        description    = "Detects BlackCat/ALPHV ransom note patterns and content"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "BlackCat"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* BlackCat ransom note phrases */
        $note_intro     = "YOUR NETWORK HAS BEEN COMPROMISED" nocase
        $note_stolen    = "Your company data has been stolen" nocase
        $note_alphv     = "ALPHV" nocase
        $note_blackcat  = "BlackCat" nocase

        /* BlackCat Tor payment portal references */
        $portal_pay     = "alphvmmm" nocase
        $portal_chat    = "ALPHV Chat" nocase

        /* BlackCat victim-specific ID */
        $victim_key     = "YOUR DECRYPTION KEY:" nocase

        /* Threat language common in BlackCat notes */
        $threat_publish = "data will be published" nocase
        $threat_stocks  = "notify investors" nocase

    condition:
        /* Company name + key ALPHV markers */
        ($note_intro or $note_stolen) and (1 of ($note_alphv, $note_blackcat, $portal_*))
        or
        /* Victim key + threat language */
        $victim_key and (1 of ($threat_*))
}


rule BlackCat_ESXi_Targeting
{
    /*
     * Detects BlackCat Linux/ESXi variant commands used to
     * enumerate and terminate VMware virtual machines before encryption.
     * The ESXi variant targets .vmdk, .vmx, and snapshot files.
     */
    meta:
        description    = "Detects BlackCat ESXi/Linux variant VM termination before encryption"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "BlackCat"
        mitre_attack   = "T1059.004"
        created        = "2024-01-01"

    strings:
        /* ESXi VM enumeration commands */
        $esxcli_list    = "esxcli vm process list" nocase
        $esxcli_kill    = "esxcli vm process kill" nocase
        $vim_cmd        = "vim-cmd vmsvc/getallvms" nocase
        $vim_power      = "vim-cmd vmsvc/power.off" nocase

        /* VMware file extension targets */
        $vmdk_ext       = ".vmdk" nocase
        $vmx_ext        = ".vmx" nocase
        $vmsn_ext       = ".vmsn" nocase

        /* BlackCat Linux target path patterns */
        $vmfs_path      = "/vmfs/volumes" nocase
        $esxi_path      = "/etc/vmware" nocase

        /* Snapshot deletion to prevent rollback */
        $snap_delete    = "vim-cmd vmsvc/snapshot.removeall" nocase

    condition:
        /* VM control commands + VMware file types */
        (($esxcli_list and $esxcli_kill) or ($vim_cmd and $vim_power))
        and (1 of ($vmdk_ext, $vmx_ext, $vmfs_path))
        or
        /* Snapshot deletion is a strong indicator on ESXi */
        $snap_delete and $vmfs_path
}
