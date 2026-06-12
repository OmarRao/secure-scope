/*
 * data_exfiltration.yar — Data Staging, Compression, and Exfiltration Patterns
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect indicators of data collection, staging, and exfiltration activity.
 *   All major double-extortion ransomware groups (Cl0p, LockBit, BlackCat, Akira)
 *   and APT actors (APT29, Lazarus, Volt Typhoon) stage and exfiltrate data
 *   before any encryption or disruptive activity.
 *
 * Coverage:
 *   - Data staging via 7-Zip, WinRAR, and archive creation commands
 *   - FTP, cURL, wget exfiltration patterns
 *   - Rclone cloud storage exfiltration (used by dozens of ransomware groups)
 *   - MEGAsync and cloud upload patterns
 *   - PowerShell/curl HTTP(S) data upload patterns
 *   - MegaSync and similar cloud sync tool abuse
 *
 * Note: String patterns may match legitimate backup or sync operations.
 *   Context is critical — evaluate alongside other indicators.
 *
 * References:
 *   MITRE ATT&CK T1560 — Archive Collected Data
 *   MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol
 *   MITRE ATT&CK T1041 — Exfiltration Over C2 Channel
 *   MITRE ATT&CK T1567 — Exfiltration Over Web Service
 */

rule DataStaging_ArchiveCreation
{
    /*
     * Detects bulk archive creation commands used to stage data for exfiltration.
     * Ransomware groups compress sensitive data (databases, financial files, PII)
     * before uploading. 7-Zip is the most commonly used tool across groups.
     */
    meta:
        description    = "Detects bulk archive creation for data staging prior to exfiltration"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Data Staging"
        mitre_attack   = "T1560.001"
        created        = "2024-01-01"

    strings:
        /* 7-Zip bulk archive creation with password (to evade DLP) */
        $sevenz_pass    = "7z a -p" nocase
        $sevenz_recurse = "7z a -r" nocase
        $sevenz_split   = "-v" nocase  /* volume splitting for large archives */

        /* WinRAR archive creation patterns */
        $rar_add        = "rar a" nocase
        $rar_recurse    = "rar a -r" nocase
        $rar_pass       = "rar a -hp" nocase  /* header-encrypted archive */

        /* PowerShell archive creation */
        $ps_compress    = "Compress-Archive" nocase
        $ps_compress_src= "-Path C:\\" nocase

        /* Targeting sensitive file types in archives */
        $target_sql     = "*.sql" nocase
        $target_mdb     = "*.mdb" nocase
        $target_xlsx    = "*.xlsx" nocase
        $target_pdf     = "*.pdf" nocase

        /* Staging directory patterns */
        $stage_dir_temp = "\\Temp\\data" nocase
        $stage_dir_pub  = "\\Public\\upload" nocase

    condition:
        /* Archive tool + password protection (evasion) */
        ($sevenz_pass or $rar_pass) and (1 of ($target_*))
        or
        /* Recursive archive with staging directory */
        ($sevenz_recurse or $rar_recurse) and (1 of ($stage_dir_*))
        or
        /* PowerShell compress from system root — unusual for legitimate use */
        ($ps_compress and $ps_compress_src)
}


rule DataExfil_Rclone
{
    /*
     * Detects Rclone usage for cloud storage exfiltration.
     * Rclone is an open-source cloud sync tool used by 50+ ransomware groups
     * including Cl0p, LockBit, Hive, BlackBasta, Akira, and Rhysida.
     * It supports Mega, AWS S3, Google Drive, Dropbox, and custom SFTP.
     */
    meta:
        description    = "Detects Rclone cloud exfiltration tool usage and configuration"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Data Exfiltration"
        mitre_attack   = "T1567.002"
        created        = "2024-01-01"

    strings:
        /* Rclone command patterns */
        $rclone_copy    = "rclone copy" nocase
        $rclone_sync    = "rclone sync" nocase
        $rclone_config  = "rclone config" nocase
        $rclone_ls      = "rclone lsd" nocase

        /* Rclone remote destination syntax */
        $rclone_mega    = "mega:" nocase
        $rclone_s3      = "s3:" nocase
        $rclone_sftp    = "sftp:" nocase
        $rclone_drive   = "drive:" nocase

        /* Rclone flags used by threat actors */
        $rclone_nomod   = "--no-check-certificate" nocase
        $rclone_bw      = "--bwlimit" nocase  /* throttle to avoid detection */
        $rclone_stats   = "--stats" nocase

        /* Rclone config file path */
        $rclone_cfg_path= "rclone.conf" nocase

    condition:
        /* Rclone copy/sync to remote destination */
        ($rclone_copy or $rclone_sync) and (1 of ($rclone_mega, $rclone_s3, $rclone_sftp, $rclone_drive))
        or
        /* Rclone config file presence + any command */
        ($rclone_cfg_path and 1 of ($rclone_copy, $rclone_sync, $rclone_ls))
}


rule DataExfil_CurlUpload
{
    /*
     * Detects cURL and wget based data upload patterns used for exfiltration.
     * APT groups and ransomware affiliates use cURL to POST stolen data
     * to attacker-controlled servers or paste services.
     */
    meta:
        description    = "Detects cURL/wget HTTP(S) data upload exfiltration patterns"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Data Exfiltration"
        mitre_attack   = "T1048.003"
        created        = "2024-01-01"

    strings:
        /* cURL upload with file attachment */
        $curl_upload_f  = "curl -F" nocase
        $curl_upload_d  = "curl -d @" nocase
        $curl_upload_t  = "curl -T" nocase  /* FTP upload */

        /* cURL with suspicious flags */
        $curl_insecure  = "curl -k" nocase  /* skip cert verification */
        $curl_silent    = "curl -s" nocase
        $curl_compress  = "curl --compressed" nocase

        /* wget upload patterns */
        $wget_post      = "wget --post-file" nocase
        $wget_method    = "wget --method=POST" nocase

        /* PowerShell upload patterns */
        $ps_upload_wb   = "Invoke-WebRequest" nocase
        $ps_post_method = "-Method POST" nocase
        $ps_infile      = "-InFile" nocase

    condition:
        /* cURL file upload */
        1 of ($curl_upload_*)
        or
        /* cURL silent + insecure (evasion flags) */
        ($curl_silent and $curl_insecure)
        or
        /* wget POST upload */
        ($wget_post or $wget_method)
        or
        /* PowerShell file upload */
        ($ps_upload_wb and $ps_post_method and $ps_infile)
}


rule DataExfil_FTP_Staging
{
    /*
     * Detects FTP-based data staging and upload commands.
     * Some ransomware groups and APT actors use FTP for bulk data transfer,
     * particularly within on-premises environments where cloud egress may be monitored.
     */
    meta:
        description    = "Detects FTP commands used for bulk data staging and exfiltration"
        author         = "SecureScope"
        severity       = "MEDIUM"
        threat_family  = "Data Exfiltration"
        mitre_attack   = "T1048.003"
        created        = "2024-01-01"

    strings:
        /* FTP bulk transfer scripts */
        $ftp_put        = "put " nocase
        $ftp_mput       = "mput *" nocase
        $ftp_binary     = "binary" nocase

        /* FTP command script creation (common in batch files) */
        $ftp_script_hdr = "open " nocase
        $ftp_script_usr = "user " nocase
        $ftp_script_bin = "bin" nocase

        /* SFTP via OpenSSH */
        $sftp_cmd       = "sftp " nocase
        $sftp_put       = "sftp -b" nocase  /* batch mode upload */

        /* PowerShell FTP upload */
        $ps_ftp         = "New-Object System.Net.WebClient" nocase
        $ps_ftp_upload  = ".UploadFile(" nocase

    condition:
        /* FTP batch script pattern */
        ($ftp_script_hdr and $ftp_script_usr and ($ftp_mput or $ftp_put))
        or
        /* SFTP batch upload */
        $sftp_put
        or
        /* PowerShell FTP upload */
        ($ps_ftp and $ps_ftp_upload)
}
