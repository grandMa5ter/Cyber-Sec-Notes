# Methodology


### 1. Discovery
[Discovering hosts inside the network](https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts)

[Discovering Assets of the company](https://book.hacktricks.xyz/external-recon-methodology)

### 2. Network
[Having Fun with the network](http:///pentesting/pentesting-network)

## (Internal)

### 3 - [Port Scan - Service discovery](https://book.hacktricks.xyz/pentesting/pentesting-network#scanning-hosts)
The first thing to do when looking for vulnerabilities in a host is to know which services are running in which ports. Let's see the []https://book.hacktricks.xyz/pentesting/pentesting-network#scanning-hosts
[basic tools to scan ports of hosts](https://book.hacktricks.xyz/pentesting/pentesting-network#scanning-hosts)

### 4 - [Searching service version exploits](https://book.hacktricks.xyz/search-exploits)
Once you know which services are running, and maybe their version, you have to search for known vulnerabilities. Maybe you get lucky and there is a exploit to give you a shell...

### 5 - Pentesting Services
If there isn't any fancy exploit for any running service, you should look for **common misconfigurations in each service running.** Inside this book you will find a guide to pentest the most common
services** (and others that aren't so common)**. Please, search in the left index the** ***PENTESTING*** **section** (the services are ordered by their default ports). **I want to make a special mention of the** [Pentesting Web](http:///pentesting/pentesting-web) **part (as it is the most extensive one).** Also, a small guide on how to [](http:///search-exploits) [find known vulnerabilities in software](http:///search-exploits) can be found here.  **If your service is not inside the index, search in Google** for other tutorials and **let me know if you want me to add it.** If you **can't
find anything** in Google, perform your **own blind pentesting**, you could start by **connecting to the service, fuzzing it and reading the
responses** (if any).

#### 5.1 Automatic Tools

There are also several tools that can perform **automatic vulnerabilities assessments**. **I would recommend you to try** [Legion](https://github.com/carlospolop/legion)**, which is the tool that I have created and it's based on the notes about pentesting services that you can find in this book.**

#### 5.2 Brute-Forcing services

In some scenarios a **Brute-Force** could be useful to **compromise** a
**service**. [Find here a CheatSheet of different services brute
forcing](http:///brute-force)**.**

### 6 - [Phishing](https://book.hacktricks.xyz/phishing-methodology)
If at this point you haven't found any interesting vulnerability you **may need to try some phishing** in order to get inside the network. You can read my phishing methodology here:
[Phishing Methodology/phishing-methodology](https://book.hacktricks.xyz/phishing-methodology)[](https://book.hacktricks.xyz/phishing-methodology)

### 7 - [Getting Shell](https://book.hacktricks.xyz/shells/shells)
Somehow you should have found **some way to execute code** in the victim. Then, [a list of possible tools inside the system that you can use to get a reverse shell would be very useful] (http:///shells/shells).   Specially in Windows you could need some help to **avoid antiviruses**: **\*\*\[**Check this page**\](windows/av-bypass.md)**.\*\*


### 8- Inside
If you have troubles with the shell, you can find here a small **compilation of the most useful commands** for pentesters:

[Linux](https://book.hacktricks.xyz/linux-unix/useful-linux-commands)​
[Windows(CMD)](https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters)​
[Winodows(PS)](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)

### 10 -[Exfiltration](https://book.hacktricks.xyz/exfiltration)
You will probably need to **extract some data from the victim** or even
**introduce something** (like privilege escalation scripts). **Here you
have a** [post about common tools that you can use with these
purposes](https://book.hacktricks.xyz/exfiltration)**.**

### 11 - Privilege Escalation

#### 11.1- Local Privesc

If you are **not root/Administrator** inside the box, you should find a way to **escalate privileges.** Here you can find a **guide to escalate privileges locally in** [Linux](http:///linux-unix/privilege-escalation) **and in** [Windows](http:///windows/windows-local-privilege-escalation)**.** You should also check this pages about how does **Windows work**:

• [Authentication, Credentials, Token privileges and UAC](http:///windows/authentication-credentials-uac-and-efs)
• How does [NTLM works](http:///windows/ntlm)
• How to [steal credentials](http:///windows/stealing-credentials) in Windows
• Some tricks about [Active Directory](http:///windows/active-directory-methodology)
**Don't forget to checkout the best tools to enumerate Windows and Linux local Privilege Escalation paths:** [Suite PEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

#### 11.2- Domain Privesc

Here you can find a [methodology explaining the most common actions to enumerate, escalate privileges and persist on an Active Directory](http:///windows/active-directory-methodology). Even if this
is just a subsection of a section, this process could be **extremely delicate** on a Pentesting/Red Team assignment.

### 12 - POST
#### 12.1 - Looting
Check if you can find more **passwords** inside the host or if you have **access to other machines** with the **privileges** of your **user**. Find here different ways to [dump passwords in
Windows](http:///windows/stealing-credentials).

#### 12.2 - Persistence
**Use 2 o 3 different types of persistence mechanism so you won't need to exploit the system again. Here you can find some** [persistence tricks on active directory](http:///windows/active-directory-methodology#persistence)**.**

### 13 - Pivoting
With the **gathered credentials** you could have access to other machines, or maybe you need to **discover and scan new hosts** (start the Pentesting Methodology again) inside new networks where your victim
is connected. In this case tunnelling could be necessary. Here you can find [a post talking about tunnelling](http:///tunneling-and-port-forwarding). You definitely should also check the post about [Active Directory pentesting Methodology](http:///windows/active-directory-methodology). There you will find cool tricks to move laterally, escalate privileges and dump credentials. Check also the page about [NTLM](http:///windows/ntlm), it could be very useful to pivot on Windows environments.. MORE[Android Applications](http:///mobile-apps-pentesting/android-app-pentesting)

## Exploiting
- [Basic Linux Exploiting](http:///exploiting/linux-exploiting-basic-esp)
- [Basic Windows Exploiting](http:///exploiting/windows-exploiting-basic-guide-oscp-lvl)
- [Basic exploiting tools](http:///exploiting/tools)
- [Basic Python](https://book.hacktricks.xyz/misc/basic-python)

## Crypto tricks
- [ECB](http:///crypto/electronic-code-book-ecb)
- [CBC-MAC](http:///crypto/cipher-block-chaining-cbc-mac-priv)
- [Padding Oracle](http:///crypto/padding-oracle-priv)
