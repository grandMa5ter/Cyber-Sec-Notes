# OSCP Notes

<!-- TOC -->
- [OSCP Notes](#oscp-notes)
  - [Training path to jedi nighthood](#training-path-to-jedi-nighthood)
  - [Usefull Stuff during CTFs](#usefull-stuff-during-ctfs)
<!-- /TOC -->

## Training path to jedi nighthood

Before I forget things and get amnesia, at least I have a copy here. And remember not all these notes are mine and I have gathered them here because I was wandering around and reading things.
**Ofcourse I haven't done this. All credit would go @TjNull for his updated blog and thorough analysis.**
  -OSCP Preparation Boxes is in the [excel files](/Offensive/files/NetSecFocus%20Trophy%20Room.xlsx)
If you need to play around with linux, [Linux Playground](/Offensive/linux-playground.md) for all linux interesting commands and operations.

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
