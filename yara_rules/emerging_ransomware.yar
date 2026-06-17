rule Play_Ransomware
{
    meta:
        description = "Detects Play ransomware (PlayCrypt) patterns — active since 2022, targets ESXi and Windows"
        author = "SecureScope"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        mitre_attack = "T1486"

    strings:
        $note1 = "ReadMe.txt" ascii
        $note2 = "PLAY" fullword ascii
        $note3 = "playrestore@" ascii nocase
        $note4 = "contact us to restore your files" ascii nocase
        $ext1 = ".PLAY" ascii
        $tool1 = "Cobalt Strike" ascii nocase
        $tool2 = "SystemBC" ascii nocase
        $tool3 = "Grixba" ascii nocase
        $tool4 = "VSS" ascii nocase
        $evasion1 = "AdFind" ascii nocase
        $evasion2 = "WinSCP" ascii nocase
        $esxi1 = "esxcli vm process kill" ascii nocase
        $esxi2 = "vim-cmd vmsvc" ascii nocase

    condition:
        ($ext1 and $note2) or
        (2 of ($note*) and 1 of ($tool*)) or
        (1 of ($esxi*) and $note2)
}

rule Akira_Ransomware
{
    meta:
        description = "Detects Akira ransomware — targets Windows and Linux/ESXi, known for double extortion"
        author = "SecureScope"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
        mitre_attack = "T1486"

    strings:
        $note1 = "akira_readme.txt" ascii nocase
        $note2 = "akiratorjh4vl5" ascii nocase
        $note3 = "your data has been encrypted" ascii nocase
        $note4 = "akirateam" ascii nocase
        $ext1 = ".akira" ascii
        $ext2 = ".powerranges" ascii
        $ransom_msg = "We're AKIRA" ascii nocase
        $linux1 = "akira_linux" ascii nocase
        $linux2 = "esxiargs" ascii nocase
        $tool1 = "WinRAR" ascii nocase
        $tool2 = "rclone" ascii nocase
        $vpn1 = "AnyDesk" ascii nocase
        $vpn2 = "Splashtop" ascii nocase

    condition:
        1 of ($ext*) or
        2 of ($note*) or
        ($ransom_msg and 1 of ($tool*))
}

rule RansomHub_Ransomware
{
    meta:
        description = "Detects RansomHub ransomware (successor to ALPHV/BlackCat) — active since 2024"
        author = "SecureScope"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"
        mitre_attack = "T1486"

    strings:
        $note1 = "README_RANSOMHUB.txt" ascii nocase
        $note2 = "ransomhub" ascii nocase
        $note3 = "RansomHub" ascii
        $note4 = "ransom-hub" ascii nocase
        $onion1 = ".onion" ascii
        $ransom_msg = "All of your files are currently encrypted" ascii nocase
        $go1 = "Go build" ascii nocase
        $go2 = "runtime.main" ascii
        $tool1 = "EDRKillShifter" ascii nocase
        $tool2 = "EDRSandBlast" ascii nocase
        $tool3 = "Bring Your Own Vulnerable Driver" ascii nocase
        $disable1 = "Disable-WindowsOptionalFeature" ascii nocase
        $disable2 = "Set-MpPreference -DisableRealtimeMonitoring" ascii nocase

    condition:
        2 of ($note*) or
        ($ransom_msg and 1 of ($onion*)) or
        (1 of ($tool*) and 1 of ($disable*))
}

rule BlackBasta_Ransomware
{
    meta:
        description = "Detects Black Basta ransomware — believed to be Conti successor, active since 2022"
        author = "SecureScope"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
        mitre_attack = "T1486"

    strings:
        $note1 = "readme.txt" ascii nocase
        $note2 = "DECRYPT" ascii nocase
        $brand1 = "Black Basta" ascii
        $brand2 = "BlackBasta" ascii
        $brand3 = "aazsbsgya2xmeil4" ascii
        $ext1 = ".basta" ascii nocase
        $tool1 = "QakBot" ascii nocase
        $tool2 = "Qbot" ascii nocase
        $tool3 = "BRc4" ascii nocase
        $tool4 = "Brute Ratel" ascii nocase
        $esxi1 = "find / -name" ascii nocase
        $esxi2 = "vmx" ascii nocase
        $vss1 = "vssadmin.exe delete shadows" ascii nocase

    condition:
        1 of ($brand*) or
        ($ext1 and 1 of ($note*)) or
        (1 of ($tool*) and $vss1)
}

rule Hunters_International_Ransomware
{
    meta:
        description = "Detects Hunters International ransomware (rebranded Hive) patterns"
        author = "SecureScope"
        mitre_attack = "T1486"

    strings:
        $note1 = "Contact.txt" ascii
        $note2 = "hunters-international" ascii nocase
        $note3 = "Contact Hunters International" ascii nocase
        $brand1 = "HuntersInternational" ascii
        $rust1 = "hunters_encryptor" ascii nocase
        $rust2 = "std::panicking" ascii
        $ext1 = ".HUNTERS" ascii nocase

    condition:
        1 of ($brand*, $ext*) or
        2 of ($note*) or
        ($rust1 and $rust2)
}
