# OSCP Notes

<!-- TOC -->
- [OSCP Notes](#oscp-notes)
  - [Training path to jedi nighthood](#training-path-to-jedi-nighthood)
  - [Dorks that would aid enumeration and exploitation](#dorks-that-would-aid-enumeration-and-exploitation)
    - [Google Dorks](#google-dorks)
    - [Specific searches](#specific-searches)
  - [Using AutoRecon](#using-autorecon)
    - [Autorecon Version 2](#autorecon-version-2)
  - [Usefull Stuff during CTFs](#usefull-stuff-during-ctfs)
  - [Exploit Dev Stuff](#exploit-dev-stuff)
<!-- /TOC -->

## Training path to jedi nighthood

Before I forget things and get amnesia, at least I have a copy here. And remember not all these notes are mine and I have gathered them here because I was wandering around and reading things.
**Ofcourse I haven't done this. All credit would go @TjNull for his updated blog and thorough analysis.**
  -OSCP Preparation Boxes is in the [excel files](/offensive/files/NetSecFocus%20Trophy%20Room.xlsx)
If you need to play around with linux, [Linux Playground](/offensive/linux-playground.md) for all linux interesting commands and operations.

## Dorks that would aid enumeration and exploitation

### Google Dorks

```text
TERM site:cvedetails.com inurl:/cve/
TERM inurl:walkthrough site:hackingarticles.in
TERM inurl:reports site:hackerone.com
TERM site:resources.infosecinstitute.com inurl:walkthrough
TERM site:medium.com inurl:(walkthrough|ctf|vulnhub) -"host a CTF" -"Hosting CTF" -"Organize a CTF"
TERM site:medium.com inurl:CVE
TERM site:blog.csdn.net inurl:details intext:(ctf|oscp|virtualhackinglabs)
TERM inurl:ctf site:bootlesshacker.com
TERM site:fdlucifer.github.io -inurl:(page and archives and categories) intext:(vulnhub|Hack-The-Box)
TERM site:book.hacktricks.xyz
```

### Specific searches

<https://github.com/swisskyrepo/PayloadsAllTheThings/search?q=TERM>
<https://twitter.com/search?q=TERM&src=typed_query>
<https://github.com/search?q=TERM>

## Using AutoRecon

The damn tool has lots of capability that I'm baffled why I didn't find it sooner. Jeez! So much time I have wasted with multiple windows and multiple codes and wait for hours to get results back. @Tib3rius hats off to you sir. Anywhere anytime, your beer is on me mate :)

Simple example: `autorecon $IP`

### Autorecon Version 2

Autorecon v2 allows you to develop plugins for scanning. [There is a python file](/offensive/files/port_scan.py) which is a sample code block for autoreconn scan plugins. Or if you fancy to go deeper and add your own services scan, then [this python file](/offensive/files/service_scan.py) gives you a bare metal code to create your own service scan module.
Then afterwards we should be able to run that with `python3 autorecon.py --plugins-dir $plugindirectory`

## Usefull Stuff during CTFs

Below are the commands that are used rarely and there are lots of write-ups but I usually forget. So I put them here for my reference and they come in handy:

1. We broke out of Jail? But shit shell?

   - You need to do the command if python is available on the target system: `python -c 'import pty; pty.spawn("/bin/bash")'`
   - If python is not available run the command: `/usr/bin/script -qc /bin/bash /dev/null`
   - Then you can examine current terminal with `echo $TERM` which should give you `xterm-256color` or something like that.
   - Then `stty -a` should give you size of TTY="rows 38;column 116". **have that in mind the command looks strange and you can't see it sometimes**
   - Then you need to press **Ctrl+z=`^z`**
   - If you are jail breaking from Normal Terminal In Kali, run the command:
       `stty raw -echo; fg`
       In reverse shell: `reset` & `export SHELL=bash` & `export TERM=<xterm256-color>` `stty rows $ROWS cols $COLS`
   - If you are jail breaking from ZSH shell In Kali, run the command:
       `stty raw -echo; fg` In reverse shell: `stty rows $ROWS cols $COLS` & `export TERM=xterm-256color` & `exec /bin/bash`

2. Using **remote desktop** from Kali `rdesktop $IP -g 95%`

## Exploit Dev Stuff

Follow [this link](/ExploitDevelopment/README.md) to get down doing some exploit development and fuzzing shit.
