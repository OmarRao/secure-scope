rule CredHarvest_BrowserCredentials
{
    meta:
        description = "Detects browser credential database theft targeting Chrome, Firefox, Edge SQLite stores"
        author = "SecureScope"
        mitre_attack = "T1555.003"

    strings:
        $chrome1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase
        $chrome2 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii nocase
        $chrome3 = "\\Chromium\\User Data\\Default\\Login Data" ascii nocase
        $edge1 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii nocase
        $firefox1 = "\\Mozilla\\Firefox\\Profiles\\" ascii nocase
        $firefox2 = "logins.json" ascii nocase
        $firefox3 = "key4.db" ascii nocase
        $opera1 = "\\Opera Software\\Opera Stable\\Login Data" ascii nocase
        $sqlite1 = "SELECT * FROM logins" ascii nocase
        $sqlite2 = "encrypted_value" ascii nocase
        $sqlite3 = "origin_url" ascii nocase
        $decrypt1 = "CryptUnprotectData" ascii nocase
        $decrypt2 = "DPAPI" ascii nocase

    condition:
        2 of ($chrome*, $edge*, $firefox*, $opera*) or
        (1 of ($chrome*, $edge*, $firefox*) and 1 of ($sqlite*)) or
        (1 of ($chrome*, $edge*, $firefox*) and 1 of ($decrypt*))
}

rule CredHarvest_DPAPI_Abuse
{
    meta:
        description = "Detects DPAPI master key extraction and credential decryption techniques"
        author = "SecureScope"
        mitre_attack = "T1555.004"

    strings:
        $dpapi1 = "Microsoft\\Protect\\S-1-5-18\\User" ascii nocase
        $dpapi2 = "CryptUnprotectData" ascii nocase
        $dpapi3 = "dpapi::masterkey" ascii nocase
        $dpapi4 = "dpapi::cred" ascii nocase
        $dpapi5 = "dpapi::blob" ascii nocase
        $dpapi6 = "dpapi::chrome" ascii nocase
        $dpapi7 = "dpapi::wifi" ascii nocase
        $mimikatz1 = "sekurlsa::dpapi" ascii nocase
        $path1 = "\\AppData\\Roaming\\Microsoft\\Protect\\" ascii nocase
        $path2 = "\\AppData\\Local\\Microsoft\\Credentials\\" ascii nocase
        $path3 = "\\AppData\\Roaming\\Microsoft\\Credentials\\" ascii nocase

    condition:
        2 of ($dpapi*) or
        $mimikatz1 or
        (1 of ($dpapi*) and 1 of ($path*))
}

rule CredHarvest_SAM_NTDS_Dump
{
    meta:
        description = "Detects SAM database and NTDS.dit extraction for offline password cracking"
        author = "SecureScope"
        mitre_attack = "T1003.002, T1003.003"

    strings:
        $sam1 = "reg save HKLM\\SAM" ascii nocase
        $sam2 = "reg save HKLM\\SYSTEM" ascii nocase
        $sam3 = "reg save HKLM\\SECURITY" ascii nocase
        $ntds1 = "ntds.dit" ascii nocase
        $ntds2 = "ntdsutil" ascii nocase
        $ntds3 = "activate instance ntds" ascii nocase
        $ntds4 = "ifm" ascii nocase
        $vss1 = "\\Windows\\NTDS\\NTDS.dit" ascii nocase
        $vss2 = "HarddiskVolumeShadowCopy" ascii nocase
        $secretsdump1 = "secretsdump" ascii nocase
        $secretsdump2 = "impacket" ascii nocase
        $creddump1 = "hashdump" ascii nocase
        $creddump2 = "fgdump" ascii nocase
        $creddump3 = "pwdump" ascii nocase

    condition:
        2 of ($sam*) or
        2 of ($ntds*) or
        ($ntds1 and $vss2) or
        1 of ($creddump*) or
        $secretsdump1
}

rule CredHarvest_Kerberoasting
{
    meta:
        description = "Detects Kerberoasting and AS-REP Roasting attacks against Active Directory"
        author = "SecureScope"
        mitre_attack = "T1558.003, T1558.004"

    strings:
        $kerb1 = "Invoke-Kerberoast" ascii nocase
        $kerb2 = "Get-DomainSPNTicket" ascii nocase
        $kerb3 = "GetUserSPNs" ascii nocase
        $kerb4 = "Rubeus.exe" ascii nocase
        $kerb5 = "kerberoast" ascii nocase
        $asrep1 = "ASREPRoast" ascii nocase
        $asrep2 = "Get-ASREPHash" ascii nocase
        $asrep3 = "Invoke-ASREPRoast" ascii nocase
        $asrep4 = "DONT_REQ_PREAUTH" ascii nocase
        $ticket1 = "kirbi" ascii nocase
        $ticket2 = "KRB5CC" ascii nocase
        $ticket3 = "pass-the-ticket" ascii nocase
        $ticket4 = "overpass-the-hash" ascii nocase

    condition:
        1 of ($kerb*) or
        1 of ($asrep*) or
        (1 of ($ticket*) and $kerb4)
}

rule CredHarvest_LSA_Secrets
{
    meta:
        description = "Detects LSA secrets extraction and cached credential theft"
        author = "SecureScope"
        mitre_attack = "T1003.004"

    strings:
        $lsa1 = "lsadump::lsa" ascii nocase
        $lsa2 = "lsadump::secrets" ascii nocase
        $lsa3 = "lsadump::cache" ascii nocase
        $lsa4 = "lsadump::sam" ascii nocase
        $lsa5 = "HKLM\\Security\\Policy\\Secrets" ascii nocase
        $cachedcreds1 = "NL$KM" ascii nocase
        $cachedcreds2 = "MSCache" ascii nocase
        $cachedcreds3 = "DCC2" ascii nocase
        $tool1 = "crackmapexec" ascii nocase
        $tool2 = "CME" fullword ascii
        $tool3 = "CrackMapExec" ascii

    condition:
        1 of ($lsa*) or
        2 of ($cachedcreds*) or
        (1 of ($tool*) and 1 of ($cachedcreds*, $lsa*))
}

rule CredHarvest_CloudCredentials
{
    meta:
        description = "Detects theft of cloud provider credentials from local metadata stores and config files"
        author = "SecureScope"
        mitre_attack = "T1552.001, T1552.005"

    strings:
        $aws1 = "\\.aws\\credentials" ascii nocase
        $aws2 = "aws_access_key_id" ascii nocase
        $aws3 = "aws_secret_access_key" ascii nocase
        $aws4 = "http://169.254.169.254/latest/meta-data/iam" ascii nocase
        $azure1 = "\\.azure\\accessTokens.json" ascii nocase
        $azure2 = "AzureCliToken" ascii nocase
        $azure3 = "Get-AzAccessToken" ascii nocase
        $gcp1 = "application_default_credentials.json" ascii nocase
        $gcp2 = "\\.config\\gcloud\\credentials" ascii nocase
        $k8s1 = "\\.kube\\config" ascii nocase
        $k8s2 = "kubeconfig" ascii nocase
        $token1 = "IMDS" ascii nocase
        $token2 = "instance metadata" ascii nocase

    condition:
        2 of ($aws*) or
        1 of ($azure*) or
        1 of ($gcp*) or
        ($k8s1 and $k8s2) or
        (1 of ($token*) and 1 of ($aws*, $azure*, $gcp*))
}
