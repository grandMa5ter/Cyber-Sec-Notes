# Customise Kali or Your OS

Following are few things I do before I use Kali or other distros that might be handy.

## Terminator Setup and quick reminder

I used Tmux and had watched videos of ippsec setting up his tmux. I feel more comfortable with terminator that tmux tbh.

```text
Infinite scrollback is selected
Profiles>colors>Change palette to "White on Black"
Profiles>Background>Solid Color
```

- Google Search plugin: <https://github.com/msudgh/terminator-search>

### Shortcuts

```text
Ctrl + Shift + O = Virtual Split
Ctrl + Shift + E = Horizontal Split

Ctrl + Shift + Z = Maximizes a current tabbed window to full screen and then restores to tabbed by pressing again
Ctrl + Shift + T = Opens a new tab

Ctrl + Shift + C = Copy to clipboard
Ctrl + Shift + V = Paste
```

## VSCode Configuration

### Colour coded test files:

- Press `Ctrl P` and run the command: `ext install xshrim.txt-syntax`
- Python exploits sometimes they are not formatted correctly. Hold `Ctrl Shift and i` to correct the formatting it.
- Install [Cheat.sh](https://marketplace.visualstudio.com/items?itemName=vscode-snippet.Snippet) for code snippets into vscode
  - Then highlight a sentence, do `Ctrl Shift S` to search for cheatsheets!

## Useful tools

There is a automated yamel project on [github](https://github.com/BrashEndeavours/hotwax) which installs and provisions extra pentesting tools on kali machine.

### Tools installed

- [Arjun](https://github.com/s0md3v/Arjun) - Arjun is an HTTP parameter discovery suite.
- [AutoRecon](https://github.com/Tib3rius/AutoRecon) - AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Six Degrees of Domain Admin.
- [chisel](https://github.com/jpillora/chisel) - A fast TCP tunnel over HTTP.
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) - The ultimate WinRM shell for hacking/pentesting.
- [gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go
- [LinEnum](https://github.com/rebootuser/LinEnum) - Local Linux Enumeration & Privilege Escalation Script
- [nishang](https://github.com/samratashok/nishang) - Framework and collection of scripts and payloads which enables usage of PowerShell for penetration testing.
- [One-Lin3r](https://github.com/D4Vinci/One-Lin3r) - On demand one-liners that aid in penetration testing operations, privilege escalation and more
- [OSCP Exam Report Template](https://github.com/whoisflynn/OSCP-Exam-Report-Template) - Modified template for the OSCP Exam
- [Powerless](https://github.com/M4ximuss/Powerless) - A Windows privilege escalation (enumeration) script designed with OSCP labs (i.e. legacy Windows machines without Powershell) in mind.
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - Collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment.
- [proxychains-ng](https://github.com/rofl0r/proxychains-ng) - proxychains ng (new generation) - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project.
- [pspy](https://github.com/DominicBreuker/pspy) - Monitor linux processes without root permissions.
- [SecLists](https://github.com/danielmiessler/SecLists) - Collection of usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and more.
- [sherlock](https://github.com/sherlock-project/sherlock) - Find usernames across social networks.
- [sshuttle](https://github.com/sshuttle/sshuttle) - Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.
- [webshell](https://github.com/tennc/webshell) - This is a webshell open source project.
- [Windows PHP Reverse Shell](https://github.com/Dhayalanb/windows-php-reverse-shell) - Simple php reverse shell implemented using bina- <https://github.com/ucki/zauberfeder>, based on an webshell.
- [XSStrike](https://github.com/s0md3v/XSStrike) - Advanced XSS scanner
- [zauberfeder](https://github.com/ucki/zauberfeder) - A LaTex reporting template.
- [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) - A swiss army knife for pentesting networks.
- [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits) - Precompiled Windows Exploits.
- [exiftool](https://github.com/exiftool/exiftool) - ExifTool meta information reader/writer.  Great for viewing and manipulating exif-data.
- [html2text](https://github.com/Alir3z4/html2text/) - Convert HTML to clean, easy-to-read plain ASCII text.
- [mingw-w64](http://mingw-w64.org/doku.php) - GCC for Windows 64 & 32 bits.
- [msfpc](https://github.com/g0tmi1k/msfpc) - MSFvenom Payload Creator (MSFPC)
- [wce](https://www.ampliasecurity.com/research/windows-credentials-editor/) - A security tool to list logon sessions and add, change, list and delete associated credentials.
- [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target.
- [pyftpdlib](https://github.com/giampaolo/pyftpdlib) - Extremely fast and scalable Python FTP server library.  Spin up FTP Server with a one-liner.
- [ssh-os](https://github.com/richlamdev/ssh-default-banners) - Nmap Script that identifies Debian, Ubuntu, FreeBSD version based on default SSH banner response.
- [empire](https://github.com/EmpireProject/Empire) - Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent.
- [medusa](http://foofus.net/goons/jmk/medusa/medusa.html) - Medusa is a speedy, parallel, modular login brute-forcer.  Similar to ncrack and Hydra.
- [PEASS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) - These tools search for possible local privilege escalation paths that you could exploit and print them to you with nice colors so you can recognize the misconfigurations easily.

### Additional tools

- [Enum4LinuxPy](https://github.com/0v3rride/Enum4LinuxPy) - The original Perl version has a number of outstanding issues that have been open for over a year and have not been addressed. This results in mangled output, errors, etc.
- [grc](https://github.com/garabik/grc) - Two programs are provided: grc and grcat. The main is grcat, which acts as a filter, i.e. taking standard input, colourising it and writing to standard output.
  - `sudo apt-get isntall grc` and then you can do this in your .zshrc `alias nmap='grc nmap'`