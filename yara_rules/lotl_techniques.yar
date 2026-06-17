rule LotL_CertUtil_Abuse
{
    meta:
        description = "Detects certutil.exe abuse for malware download and encoding — common LOLBin technique"
        author = "SecureScope"
        mitre_attack = "T1105, T1140"

    strings:
        $certutil1 = "certutil" ascii nocase
        $dl1 = "-urlcache" ascii nocase
        $dl2 = "-split" ascii nocase
        $dl3 = "-f http" ascii nocase
        $dl4 = "-f ftp" ascii nocase
        $enc1 = "-decode" ascii nocase
        $enc2 = "-encode" ascii nocase
        $enc3 = "-decodehex" ascii nocase
        $sus_path1 = "\\Temp\\" ascii nocase
        $sus_path2 = "\\AppData\\" ascii nocase
        $sus_path3 = "\\Public\\" ascii nocase

    condition:
        $certutil1 and (1 of ($dl*) or 1 of ($enc*)) and 1 of ($sus_path*)
}

rule LotL_MSHTA_Abuse
{
    meta:
        description = "Detects mshta.exe abuse for executing remote HTA payloads"
        author = "SecureScope"
        mitre_attack = "T1218.005"

    strings:
        $mshta1 = "mshta.exe" ascii nocase
        $mshta2 = "mshta " ascii nocase
        $remote1 = "http://" ascii nocase
        $remote2 = "https://" ascii nocase
        $remote3 = "ftp://" ascii nocase
        $vb1 = "VBScript" ascii nocase
        $vb2 = "javascript:" ascii nocase
        $vb3 = "vbscript:" ascii nocase
        $inline1 = "mshta vbscript:" ascii nocase
        $inline2 = "mshta javascript:" ascii nocase

    condition:
        1 of ($inline*) or
        (1 of ($mshta*) and 1 of ($remote*)) or
        (1 of ($mshta*) and 2 of ($vb*))
}

rule LotL_Regsvr32_Squiblydoo
{
    meta:
        description = "Detects regsvr32.exe Squiblydoo technique — executing remote COM scriptlets"
        author = "SecureScope"
        mitre_attack = "T1218.010"

    strings:
        $r1 = "regsvr32" ascii nocase
        $s1 = "/s /n /u /i:http" ascii nocase
        $s2 = "/s /i:http" ascii nocase
        $s3 = "scrobj.dll" ascii nocase
        $s4 = ".sct" ascii nocase
        $remote1 = "http://" ascii nocase
        $remote2 = "https://" ascii nocase

    condition:
        $r1 and (1 of ($s*)) and 1 of ($remote*)
}

rule LotL_Wscript_Cscript_Abuse
{
    meta:
        description = "Detects wscript/cscript abuse for payload execution from suspicious locations"
        author = "SecureScope"
        mitre_attack = "T1059.005"

    strings:
        $ws1 = "wscript.exe" ascii nocase
        $cs1 = "cscript.exe" ascii nocase
        $sus_path1 = "\\Temp\\" ascii nocase
        $sus_path2 = "\\AppData\\Roaming\\" ascii nocase
        $sus_path3 = "\\Public\\" ascii nocase
        $sus_path4 = "\\Downloads\\" ascii nocase
        $ext1 = ".vbs" ascii nocase
        $ext2 = ".js" ascii nocase
        $ext3 = ".jse" ascii nocase
        $ext4 = ".vbe" ascii nocase
        $dl1 = "XMLHTTP" ascii nocase
        $dl2 = "WinHttp" ascii nocase
        $dl3 = "Msxml2.ServerXMLHTTP" ascii nocase

    condition:
        (1 of ($ws*, $cs*)) and
        (1 of ($sus_path*)) and
        (1 of ($ext*) or 1 of ($dl*))
}

rule LotL_BitsAdmin_Download
{
    meta:
        description = "Detects bitsadmin abuse for stealthy file downloads"
        author = "SecureScope"
        mitre_attack = "T1197"

    strings:
        $bits1 = "bitsadmin" ascii nocase
        $dl1 = "/transfer" ascii nocase
        $dl2 = "/download" ascii nocase
        $dl3 = "http://" ascii nocase
        $dl4 = "https://" ascii nocase
        $sus_path1 = "\\Temp\\" ascii nocase
        $sus_path2 = "\\AppData\\" ascii nocase
        $sus_path3 = "C:\\Windows\\Temp" ascii nocase
        $exec1 = "/complete" ascii nocase
        $exec2 = "/resume" ascii nocase

    condition:
        $bits1 and (1 of ($dl*)) and (1 of ($sus_path*) or 1 of ($exec*))
}

rule LotL_PowerShell_DownloadCradle
{
    meta:
        description = "Detects PowerShell download cradles used for fileless malware staging"
        author = "SecureScope"
        mitre_attack = "T1059.001, T1105"

    strings:
        $iex1 = "IEX" fullword ascii nocase
        $iex2 = "Invoke-Expression" ascii nocase
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $dl3 = "WebClient" ascii nocase
        $dl4 = "Net.WebClient" ascii nocase
        $dl5 = "Invoke-WebRequest" ascii nocase
        $dl6 = "iwr " ascii nocase
        $obf1 = "-EncodedCommand" ascii nocase
        $obf2 = "-enc " ascii nocase
        $obf3 = "-nop " ascii nocase
        $obf4 = "-noprofile" ascii nocase
        $obf5 = "-windowstyle hidden" ascii nocase
        $obf6 = "-NonInteractive" ascii nocase

    condition:
        (1 of ($iex*) and 1 of ($dl*)) or
        (1 of ($dl*) and 2 of ($obf*)) or
        ($obf1 and 1 of ($obf2, $obf3, $obf5))
}

rule LotL_Rundll32_Abuse
{
    meta:
        description = "Detects rundll32.exe abuse for executing malicious DLLs and LOLBAS techniques"
        author = "SecureScope"
        mitre_attack = "T1218.011"

    strings:
        $r1 = "rundll32" ascii nocase
        $lol1 = "javascript:" ascii nocase
        $lol2 = "vbscript:" ascii nocase
        $lol3 = "shell32.dll,ShellExec_RunDLL" ascii nocase
        $lol4 = "advpack.dll,LaunchINFSection" ascii nocase
        $lol5 = "ieadvpack.dll" ascii nocase
        $lol6 = "shdocvw.dll,OpenURL" ascii nocase
        $remote1 = "http://" ascii nocase
        $remote2 = "https://" ascii nocase
        $sus_path1 = "\\Temp\\" ascii nocase
        $sus_path2 = "\\AppData\\" ascii nocase

    condition:
        $r1 and (1 of ($lol*) or (1 of ($remote*) and 1 of ($sus_path*)))
}
