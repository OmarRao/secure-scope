/*
 * ransomware_common.yar — Common Ransomware Behavioural Indicators
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect generic ransomware behaviour patterns that are common across
 *   many families regardless of specific payload. Rules cover:
 *     - File extension manipulation patterns used after encryption
 *     - Ransom note filename and content patterns
 *     - Shadow copy / VSS deletion commands
 *     - Windows CryptoAPI usage patterns typical of encryption loops
 *
 * Coverage:
 *   Generic / family-agnostic ransomware indicators
 *   Suitable for scanning backup directories, staging areas, and file servers
 *
 * Note: These rules use realistic but non-functional string patterns.
 *   They are intended for demonstration and educational purposes within
 *   SecureScope. False positive rate should be evaluated before production use.
 *
 * References:
 *   MITRE ATT&CK T1486 — Data Encrypted for Impact
 *   MITRE ATT&CK T1490 — Inhibit System Recovery
 */

rule Ransomware_FileExtensionChange
{
    /*
     * Detects scripts or binaries that perform bulk file extension renaming,
     * a near-universal ransomware behaviour after encryption is complete.
     * Matches on PowerShell Rename-Item loops and cmd batch rename patterns.
     */
    meta:
        description    = "Detects bulk file extension rename patterns used post-encryption"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Ransomware Generic"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* PowerShell rename loop — common in script-based ransomware */
        $ps_rename_loop = "Rename-Item" nocase
        $ps_foreach     = "ForEach-Object" nocase
        $ps_ext_change  = /\.\w{3,8}\"/ nocase

        /* CMD batch rename patterns */
        $cmd_ren        = "ren " nocase
        $cmd_for_files  = "for /r" nocase

        /* Common ransomware extension markers */
        $ext_locked     = ".locked" nocase
        $ext_encrypted  = ".encrypted" nocase
        $ext_enc        = ".enc" nocase
        $ext_crypto     = ".crypto" nocase

    condition:
        /* Require rename capability + at least one suspicious extension marker */
        (($ps_rename_loop and $ps_foreach) or ($cmd_ren and $cmd_for_files))
        and (1 of ($ext_*))
}


rule Ransomware_NotePattern
{
    /*
     * Detects ransom note creation patterns — both the file names commonly
     * used and content patterns found inside ransom notes.
     * Covers HTML, TXT, and HTA ransom note formats.
     */
    meta:
        description    = "Detects ransom note filename and content patterns"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Ransomware Generic"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* Common ransom note filenames */
        $note_howto     = "HOW_TO_DECRYPT" nocase
        $note_readme    = "README_FOR_DECRYPT" nocase
        $note_restore   = "RESTORE_FILES" nocase
        $note_recover   = "RECOVERY_INSTRUCTIONS" nocase
        $note_important = "IMPORTANT_NOTICE" nocase

        /* Common ransom note content phrases */
        $phrase_encrypted   = "your files have been encrypted" nocase
        $phrase_bitcoin     = "bitcoin" nocase
        $phrase_tor_browser = "tor browser" nocase
        $phrase_unique_id   = "unique ID" nocase
        $phrase_decryption  = "decryption key" nocase
        $phrase_deadline    = "within 72 hours" nocase

        /* HTML/HTA ransom note structural markers */
        $html_ransom    = "<html>" nocase
        $html_decrypt   = "decrypt" nocase

    condition:
        /* Note filename + at least 2 content phrases */
        (1 of ($note_*)) and (2 of ($phrase_*))
        or
        /* HTML note: structural HTML + decryption reference */
        ($html_ransom and $html_decrypt and 1 of ($phrase_*))
}


rule Ransomware_ShadowCopyDeletion
{
    /*
     * Detects commands used to delete Volume Shadow Copies (VSS) —
     * a near-universal ransomware technique to prevent system recovery.
     * Covers vssadmin, wmic, PowerShell, and bcdedit variants.
     */
    meta:
        description    = "Detects VSS/shadow copy deletion commands used to inhibit recovery"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Ransomware Generic"
        mitre_attack   = "T1490"
        created        = "2024-01-01"

    strings:
        /* vssadmin delete shadows — most common form */
        $vss_delete     = "vssadmin delete shadows" nocase
        $vss_resize     = "vssadmin resize shadowstorage" nocase

        /* WMIC shadow copy deletion */
        $wmic_shadow    = "wmic shadowcopy delete" nocase
        $wmic_shadows   = "WMIC.exe shadowcopy" nocase

        /* PowerShell VSS deletion */
        $ps_vss         = "Get-WmiObject Win32_ShadowCopy" nocase
        $ps_delete_vss  = ".Delete()" nocase

        /* bcdedit — disables Windows Recovery Environment */
        $bcdedit_re     = "bcdedit /set {default} recoveryenabled no" nocase
        $bcdedit_boot   = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase

        /* wbadmin — disables Windows Backup */
        $wbadmin        = "wbadmin delete catalog" nocase

    condition:
        /* Any VSS/recovery deletion command is a strong indicator */
        any of them
}


rule Ransomware_EncryptionAPI
{
    /*
     * Detects Windows CryptoAPI function call patterns commonly used in
     * ransomware encryption routines. Matches import table entries and
     * inline string references to cryptographic API functions.
     * Note: These APIs are also used by legitimate software — use in context.
     */
    meta:
        description    = "Detects Windows CryptoAPI usage patterns in ransomware encryption loops"
        author         = "SecureScope"
        severity       = "MEDIUM"
        threat_family  = "Ransomware Generic"
        mitre_attack   = "T1486"
        created        = "2024-01-01"

    strings:
        /* CryptEncrypt / CryptDecrypt API references */
        $crypt_encrypt  = "CryptEncrypt" nocase
        $crypt_genkey   = "CryptGenKey" nocase
        $crypt_export   = "CryptExportKey" nocase
        $crypt_acquire  = "CryptAcquireContext" nocase

        /* BCrypt API (newer ransomware families) */
        $bcrypt_open    = "BCryptOpenAlgorithmProvider" nocase
        $bcrypt_gen     = "BCryptGenerateSymmetricKey" nocase
        $bcrypt_enc     = "BCryptEncrypt" nocase

        /* AES-256 marker bytes in key schedule (hex pattern) */
        $aes256_sbox    = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }

        /* Common ransomware key generation entropy source */
        $rand_gen       = "CryptGenRandom" nocase
        $rand_bcrypt    = "BCryptGenRandom" nocase

    condition:
        /* Require multiple crypto API references together — reduces false positives */
        (
            ($crypt_encrypt and $crypt_genkey and $crypt_acquire)
            or
            ($bcrypt_open and $bcrypt_gen and $bcrypt_enc)
        )
        or
        /* AES S-box bytes with key generation — strong indicator */
        ($aes256_sbox and ($rand_gen or $rand_bcrypt))
}
