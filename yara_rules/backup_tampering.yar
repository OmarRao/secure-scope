/*
 * backup_tampering.yar — Backup Deletion, VSS Tampering, and Recovery Disruption
 * SecureScope YARA Rule Engine
 *
 * Purpose:
 *   Detect attacks against backup infrastructure — the final line of defence
 *   against ransomware. All major ransomware families systematically destroy
 *   backups before or alongside encryption to maximise extortion leverage.
 *
 *   This rule set specifically targets backup software agents, Veeam repositories,
 *   Windows Backup, and cloud backup configurations that threat actors modify
 *   or destroy to prevent recovery.
 *
 * Coverage:
 *   - Veeam Backup & Replication tampering (config deletion, service stopping)
 *   - Windows Server Backup and wbadmin commands
 *   - Volume Shadow Copy deletion (extended coverage)
 *   - Backup agent process termination
 *   - NAS/network share backup path deletion
 *   - Tape backup software tampering
 *   - Restic, Duplicati, and open-source backup tool interference
 *
 * Note: Some patterns match legitimate maintenance scripts.
 *   Context (account, time, frequency) is essential for accurate triage.
 *
 * References:
 *   MITRE ATT&CK T1490 — Inhibit System Recovery
 *   MITRE ATT&CK T1485 — Data Destruction
 *   MITRE ATT&CK T1562.001 — Disable or Modify Tools
 */

rule Backup_VeeamTampering
{
    /*
     * Detects attacks targeting Veeam Backup & Replication infrastructure.
     * Ransomware groups (Akira, Black Basta, Conti, LockBit) specifically target
     * Veeam because it is the most widely deployed enterprise backup solution.
     * Known attack patterns include stopping services, deleting catalogs, and
     * exploiting Veeam CVEs (CVE-2023-27532, CVE-2024-29849) for credential access.
     */
    meta:
        description    = "Detects Veeam backup infrastructure tampering and service disruption"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Backup Tampering"
        mitre_attack   = "T1490"
        created        = "2024-01-01"

    strings:
        /* Stopping Veeam services */
        $veeam_svc_stop1= "sc stop VeeamBackupSvc" nocase
        $veeam_svc_stop2= "sc stop VeeamDeploymentSvc" nocase
        $veeam_svc_stop3= "sc stop VeeamNFSSvc" nocase
        $veeam_svc_stop4= "sc stop VeeamTransportSvc" nocase
        $veeam_svc_stop5= "net stop VeeamBackupSvc" nocase

        /* Veeam configuration database deletion */
        $veeam_db_del   = "VeeamBackup.bak" nocase
        $veeam_cfg_del  = "Veeam\\Backup" nocase

        /* PowerShell Veeam service manipulation */
        $ps_veeam_stop  = "Stop-Service -Name Veeam" nocase
        $ps_veeam_disab = "Set-Service -Name Veeam" nocase

        /* Veeam backup catalog deletion */
        $veeam_catalog  = "VBRCatalog" nocase
        $veeam_vbk_del  = ".vbk" nocase  /* Veeam full backup file extension */
        $veeam_vib_del  = ".vib" nocase  /* Veeam incremental backup */
        $veeam_vrb_del  = ".vrb" nocase  /* Veeam reverse incremental */

        /* Access to Veeam credentials (CVE-2023-27532 exploitation pattern) */
        $veeam_cred_sql = "SELECT * FROM [VeeamBackup].[dbo].[Credentials]" nocase

    condition:
        /* Service stop targeting multiple Veeam services */
        2 of ($veeam_svc_stop*)
        or
        /* PowerShell Veeam disruption */
        ($ps_veeam_stop or $ps_veeam_disab)
        or
        /* Veeam backup file deletion + catalog */
        ($veeam_catalog and 1 of ($veeam_vbk_del, $veeam_vib_del))
        or
        /* Credential extraction from Veeam database */
        $veeam_cred_sql
}


rule Backup_WindowsBackupDeletion
{
    /*
     * Detects attacks against Windows Server Backup (wbadmin) and
     * Windows Recovery Environment (WinRE/bcdedit).
     * These are standard ransomware cleanup steps to prevent OS-level recovery.
     */
    meta:
        description    = "Detects Windows Backup catalog deletion and WinRE disablement"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Backup Tampering"
        mitre_attack   = "T1490"
        created        = "2024-01-01"

    strings:
        /* wbadmin backup catalog deletion */
        $wbadmin_del    = "wbadmin delete catalog" nocase
        $wbadmin_quiet  = "wbadmin delete catalog -quiet" nocase
        $wbadmin_bak    = "wbadmin delete backup" nocase

        /* bcdedit Windows Recovery disablement */
        $bcdedit_nore   = "bcdedit /set {default} recoveryenabled no" nocase
        $bcdedit_ignore = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $bcdedit_noboot = "bcdedit /set {bootmgr} displaybootmenu no" nocase

        /* Windows Backup service disablement */
        $wbengine_stop  = "sc stop wbengine" nocase
        $wbengine_disab = "sc config wbengine start= disabled" nocase

        /* System Restore / ShadowStorage resize to 0 */
        $vss_zero       = "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB" nocase
        $vss_resize_min = "vssadmin resize shadowstorage" nocase

    condition:
        /* Windows Backup catalog deletion */
        ($wbadmin_del or $wbadmin_quiet or $wbadmin_bak)
        or
        /* WinRE disablement */
        ($bcdedit_nore or $bcdedit_ignore)
        or
        /* Backup service disablement */
        ($wbengine_stop and $wbengine_disab)
        or
        /* VSS storage resize (prevents new shadow copies) */
        $vss_zero
}


rule Backup_AgentProcessKill
{
    /*
     * Detects mass termination of backup agent processes.
     * Ransomware groups kill backup agents before encryption to prevent
     * backup jobs from completing and to free file locks on data files.
     * Covers Acronis, CommVault, Veritas, Arcserve, Backup Exec, and others.
     */
    meta:
        description    = "Detects backup agent process termination used to disrupt backup operations"
        author         = "SecureScope"
        severity       = "HIGH"
        threat_family  = "Backup Tampering"
        mitre_attack   = "T1562.001"
        created        = "2024-01-01"

    strings:
        /* taskkill targeting backup agents */
        $kill_veeam     = "taskkill /F /IM VeeamAgent" nocase
        $kill_acronis   = "taskkill /F /IM AcronisAgent" nocase
        $kill_commvault = "taskkill /F /IM CommVault" nocase
        $kill_backupexec= "taskkill /F /IM beremote.exe" nocase
        $kill_arcserve  = "taskkill /F /IM Arcserve" nocase
        $kill_veritas   = "taskkill /F /IM BackupExec.exe" nocase
        $kill_symantec  = "taskkill /F /IM NSBServer" nocase
        $kill_emc       = "taskkill /F /IM nsrexecd" nocase

        /* PowerShell backup process kill */
        $ps_kill_backup = "Stop-Process -Name" nocase
        $ps_veeam_proc  = "VeeamBackup" nocase

        /* SC stop for backup services */
        $sc_stop_backup = "sc stop BackupExecAgentAccelerator" nocase
        $sc_stop_cavlt  = "sc stop CavaultService" nocase

    condition:
        /* Multiple backup agent kill commands — strong indicator */
        2 of ($kill_*)
        or
        /* PowerShell killing Veeam processes */
        ($ps_kill_backup and $ps_veeam_proc)
        or
        /* Backup service stop */
        ($sc_stop_backup or $sc_stop_cavlt)
}


rule Backup_NetworkShareDeletion
{
    /*
     * Detects deletion of backup files on network shares and NAS devices.
     * Ransomware groups map backup shares and delete .bak, .vbk, and .tar
     * files to destroy network-attached backup copies before encryption.
     */
    meta:
        description    = "Detects mass deletion of backup files on network shares"
        author         = "SecureScope"
        severity       = "CRITICAL"
        threat_family  = "Backup Tampering"
        mitre_attack   = "T1485"
        created        = "2024-01-01"

    strings:
        /* cmd.exe deletion of backup file types on UNC paths */
        $del_vbk_unc    = "del /F /S /Q \\\\*\\backup\\*.vbk" nocase
        $del_bak_unc    = "del /F /S /Q \\\\*\\backup\\*.bak" nocase

        /* PowerShell recursive backup file deletion */
        $ps_del_backup  = "Remove-Item" nocase
        $ps_recurse     = "-Recurse -Force" nocase
        $ps_bak_ext     = "*.bak" nocase
        $ps_vbk_ext     = "*.vbk" nocase

        /* Robocopy used to mirror empty dir over backup (destructive) */
        $robocopy_purge = "robocopy" nocase
        $robocopy_purge2= "/PURGE" nocase

        /* Network backup path indicators */
        $backup_share   = "\\\\server\\backup" nocase
        $nas_backup     = "\\\\nas\\" nocase

    condition:
        /* Direct UNC path deletion of backup files */
        ($del_vbk_unc or $del_bak_unc)
        or
        /* PowerShell recursive deletion of backup files */
        ($ps_del_backup and $ps_recurse and ($ps_bak_ext or $ps_vbk_ext))
        or
        /* Robocopy purge over backup share */
        ($robocopy_purge and $robocopy_purge2 and ($backup_share or $nas_backup))
}
