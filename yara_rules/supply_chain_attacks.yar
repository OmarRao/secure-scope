rule SupplyChain_DependencyConfusion
{
    meta:
        description = "Detects dependency confusion attack artifacts — malicious packages mimicking internal package names"
        author = "SecureScope"
        mitre_attack = "T1195.001"

    strings:
        $setup1 = "setup.py" ascii
        $npm1 = "package.json" ascii
        $exfil1 = "os.environ" ascii nocase
        $exfil2 = "subprocess" ascii nocase
        $exfil3 = "requests.post" ascii nocase
        $exfil4 = "urllib.request" ascii nocase
        $collect1 = "socket.gethostname" ascii nocase
        $collect2 = "platform.node" ascii nocase
        $collect3 = "getpass.getuser" ascii nocase
        $collect4 = "os.getlogin" ascii nocase
        $install_hook1 = "install_requires" ascii nocase
        $install_hook2 = "cmdclass" ascii nocase
        $install_hook3 = "postinstall" ascii nocase
        $dns_exfil1 = "dns.resolver" ascii nocase
        $dns_exfil2 = ".burpcollaborator" ascii nocase
        $dns_exfil3 = ".canarytokens" ascii nocase
        $dns_exfil4 = ".interact.sh" ascii nocase

    condition:
        (1 of ($setup*, $npm*)) and
        (
            (2 of ($collect*) and 1 of ($exfil*)) or
            1 of ($dns_exfil*) or
            (1 of ($install_hook*) and 1 of ($exfil*))
        )
}

rule SupplyChain_CICDTampering
{
    meta:
        description = "Detects CI/CD pipeline tampering — malicious modifications to GitHub Actions, GitLab CI, or Jenkins"
        author = "SecureScope"
        mitre_attack = "T1195.002, T1053.007"

    strings:
        $gh_actions1 = ".github/workflows" ascii nocase
        $gh_actions2 = "uses: actions/" ascii nocase
        $gh_actions3 = "GITHUB_TOKEN" ascii nocase
        $gl_ci1 = ".gitlab-ci.yml" ascii nocase
        $jenkins1 = "Jenkinsfile" ascii nocase
        $sus_cmd1 = "curl | bash" ascii nocase
        $sus_cmd2 = "curl | sh" ascii nocase
        $sus_cmd3 = "wget -O- | bash" ascii nocase
        $sus_cmd4 = "wget -O- | sh" ascii nocase
        $cred_leak1 = "echo $GITHUB_TOKEN" ascii nocase
        $cred_leak2 = "echo $CI_JOB_TOKEN" ascii nocase
        $cred_leak3 = "printenv" ascii nocase
        $exfil1 = "requests.post" ascii nocase
        $exfil2 = "curl -X POST" ascii nocase
        $exfil3 = "Invoke-WebRequest -Method POST" ascii nocase
        $secrets1 = "${{ secrets." ascii
        $env_dump1 = "env | base64" ascii nocase

    condition:
        (1 of ($gh_actions*, $gl_ci*, $jenkins*)) and
        (
            1 of ($sus_cmd*) or
            1 of ($cred_leak*) or
            (1 of ($secrets*) and 1 of ($exfil*)) or
            $env_dump1
        )
}

rule SupplyChain_MaliciousNpmPackage
{
    meta:
        description = "Detects malicious npm package patterns — postinstall exfil, obfuscated loaders"
        author = "SecureScope"
        mitre_attack = "T1195.001"

    strings:
        $postinstall1 = "\"postinstall\":" ascii nocase
        $postinstall2 = "\"preinstall\":" ascii nocase
        $exec1 = "child_process" ascii nocase
        $exec2 = "exec(" ascii nocase
        $exec3 = "execSync(" ascii nocase
        $exec4 = "spawn(" ascii nocase
        $net1 = "require('https')" ascii nocase
        $net2 = "require(\"https\")" ascii nocase
        $net3 = "require('http')" ascii nocase
        $net4 = "require(\"http\")" ascii nocase
        $env1 = "process.env" ascii nocase
        $sys1 = "os.homedir()" ascii nocase
        $sys2 = "os.hostname()" ascii nocase
        $sys3 = "os.userInfo()" ascii nocase
        $obf1 = "Buffer.from(" ascii nocase
        $obf2 = ".toString('base64')" ascii nocase
        $obf3 = "atob(" ascii nocase
        $obf4 = "eval(Buffer" ascii nocase

    condition:
        (1 of ($postinstall*)) and
        (
            (1 of ($exec*) and 1 of ($net*)) or
            (2 of ($sys*) and 1 of ($net*)) or
            (1 of ($env*) and 1 of ($net*) and 1 of ($obf*))
        )
}

rule SupplyChain_GitSubmoduleTampering
{
    meta:
        description = "Detects Git submodule and subrepository tampering patterns used in supply chain attacks"
        author = "SecureScope"
        mitre_attack = "T1195.002"

    strings:
        $submod1 = ".gitmodules" ascii
        $submod2 = "[submodule " ascii
        $submod3 = "git submodule update" ascii nocase
        $sus_url1 = "raw.githubusercontent.com" ascii nocase
        $sus_url2 = "pastebin.com" ascii nocase
        $sus_url3 = "paste.ee" ascii nocase
        $sus_url4 = "ghostbin.co" ascii nocase
        $hook1 = ".git/hooks/post-checkout" ascii nocase
        $hook2 = ".git/hooks/pre-commit" ascii nocase
        $hook3 = ".git/hooks/post-merge" ascii nocase
        $hook4 = ".git/hooks/post-receive" ascii nocase
        $exec1 = "#!/bin/bash" ascii
        $exec2 = "#!/bin/sh" ascii

    condition:
        (1 of ($hook*) and 1 of ($exec*)) or
        (1 of ($submod*) and 1 of ($sus_url*))
}

rule SupplyChain_MaliciousPyPIPackage
{
    meta:
        description = "Detects malicious PyPI package patterns — setup.py exfil hooks, obfuscated loaders"
        author = "SecureScope"
        mitre_attack = "T1195.001"

    strings:
        $setup1 = "setup.py" ascii
        $hook1 = "install_requires" ascii nocase
        $hook2 = "cmdclass" ascii nocase
        $hook3 = "class install(" ascii nocase
        $hook4 = "def run(self)" ascii nocase
        $import1 = "import os" ascii nocase
        $import2 = "import socket" ascii nocase
        $import3 = "import subprocess" ascii nocase
        $net1 = "urllib.request.urlopen" ascii nocase
        $net2 = "requests.get" ascii nocase
        $net3 = "requests.post" ascii nocase
        $env1 = "os.environ" ascii nocase
        $env2 = "os.getenv" ascii nocase
        $b64_1 = "base64.b64decode" ascii nocase
        $b64_2 = "__import__('base64')" ascii nocase
        $exec1 = "exec(compile(" ascii nocase
        $exec2 = "eval(compile(" ascii nocase

    condition:
        $setup1 and
        (1 of ($hook*)) and
        (
            (1 of ($net*) and 1 of ($env*)) or
            1 of ($exec*) or
            ($b64_1 and 1 of ($net*))
        )
}

rule SupplyChain_DockerImageTampering
{
    meta:
        description = "Detects suspicious Dockerfile patterns used in poisoned container images"
        author = "SecureScope"
        mitre_attack = "T1195.002"

    strings:
        $df1 = "FROM " ascii
        $sus1 = "curl | bash" ascii nocase
        $sus2 = "wget -O- | sh" ascii nocase
        $sus3 = "curl | sh" ascii nocase
        $cron1 = "crontab" ascii nocase
        $cron2 = "* * * * *" ascii
        $rev_shell1 = "bash -i >& /dev/tcp/" ascii nocase
        $rev_shell2 = "nc -e /bin/bash" ascii nocase
        $rev_shell3 = "ncat --exec" ascii nocase
        $exfil1 = "cat /etc/passwd" ascii nocase
        $exfil2 = "cat /etc/shadow" ascii nocase
        $exfil3 = "/proc/self/environ" ascii nocase
        $miner1 = "xmrig" ascii nocase
        $miner2 = "cryptonight" ascii nocase
        $miner3 = "monero" ascii nocase

    condition:
        $df1 and (
            1 of ($sus*) or
            1 of ($rev_shell*) or
            ($cron1 and $cron2) or
            2 of ($exfil*) or
            1 of ($miner*)
        )
}
