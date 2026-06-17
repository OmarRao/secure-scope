rule Clop_RansomNote
{
    meta:
        description = "Detects Cl0p ransomware ransom note patterns and branding"
        author = "SecureScope"
        reference = "https://attack.mitre.org/software/S0611/"
        mitre_attack = "T1486"

    strings:
        $note1 = "ClopReadMe.txt" ascii nocase
        $note2 = "CIop_README_" ascii nocase
        $note3 = "Your network has been hacked and encrypted" ascii nocase
        $note4 = "clop@" ascii nocase
        $note5 = "don't waste time" ascii nocase
        $note6 = "We are the only ones who can decrypt" ascii nocase
        $brand1 = "Cl0p" ascii
        $brand2 = "ClopDecryptor" ascii nocase
        $brand3 = "clop_readme" ascii nocase
        $ext1 = ".Clop" ascii
        $ext2 = ".CIOP" ascii

    condition:
        2 of ($note*) or 1 of ($brand*) or 1 of ($ext*)
}

rule Clop_MOVEit_Exploitation
{
    meta:
        description = "Detects Cl0p MOVEit Transfer exploitation patterns (CVE-2023-34362)"
        author = "SecureScope"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"
        mitre_attack = "T1190"
        cve = "CVE-2023-34362"

    strings:
        $moveit1 = "MOVEit" ascii nocase
        $moveit2 = "moveitisapi" ascii nocase
        $moveit3 = "human2.aspx" ascii nocase
        $moveit4 = "X-siLock-Comment" ascii nocase
        $sqli1 = "';WAITFOR DELAY" ascii nocase
        $sqli2 = "xp_cmdshell" ascii nocase
        $webshell1 = "Tiny.aspx" ascii nocase
        $webshell2 = "LemurLoot" ascii nocase
        $webshell3 = "LEMURLOOT" ascii nocase
        $exfil1 = "zipfiles" ascii nocase
        $exfil2 = "GetFile" ascii nocase

    condition:
        ($moveit1 or $moveit2) and (1 of ($sqli*) or 1 of ($webshell*) or 1 of ($exfil*))
}

rule Clop_GoAnywhere_Exploitation
{
    meta:
        description = "Detects Cl0p GoAnywhere MFT exploitation patterns (CVE-2023-0669)"
        author = "SecureScope"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0669"
        mitre_attack = "T1190"
        cve = "CVE-2023-0669"

    strings:
        $ga1 = "GoAnywhere" ascii nocase
        $ga2 = "goanywhere" ascii nocase
        $ga3 = "/goanywhere/" ascii nocase
        $rce1 = "com.fortra.goanywhere" ascii nocase
        $rce2 = "LicenseResponseServlet" ascii nocase
        $rce3 = "DecryptionHandler" ascii nocase
        $payload1 = "com.clopclop" ascii nocase
        $payload2 = "Truebot" ascii nocase
        $payload3 = "FlawedGrace" ascii nocase

    condition:
        1 of ($ga*) and (1 of ($rce*) or 1 of ($payload*))
}

rule Clop_DefenceEvasion
{
    meta:
        description = "Detects Cl0p defence evasion and anti-analysis techniques"
        author = "SecureScope"
        mitre_attack = "T1562.001"

    strings:
        $av1 = "SentinelOne" ascii nocase
        $av2 = "CrowdStrike" ascii nocase
        $disable1 = "sc stop" ascii nocase
        $disable2 = "net stop" ascii nocase
        $disable3 = "taskkill /F /IM" ascii nocase
        $clop_mutex = "Fud_Mutex_Sumsung_100" ascii
        $clop_key = "CLOP" fullword ascii
        $clop_ext_chk = ".Clop" ascii nocase
        $wipe1 = "wevtutil cl System" ascii nocase
        $wipe2 = "wevtutil cl Security" ascii nocase
        $wipe3 = "wevtutil cl Application" ascii nocase

    condition:
        $clop_mutex or $clop_key or
        (($clop_ext_chk) and 2 of ($disable*, $av*, $wipe*))
}
