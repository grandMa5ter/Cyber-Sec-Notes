# Cyber-Sec-Notes

Just a small note takin page that keep adding to it. For shits and giggles later:

PowerShell-based penetration testing tools:
- Empire
- Apfell
- Covenant
- Silver
- Faction

## How to use remote desktop from Kali:

````
rdesktop $IP -g 95%
````

## How to install python 2 on Kali 2020.x onwards:

download the bloody get-pip.py from here:
````
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
pip install --upgrade setuptools
sudo pip install --upgrade setuptools
sudo pip2 install #[py 2 package]
````

## Setting up the terminator for Kali 2020.x onwards:

  > sudo apt install terminator

Or if they don't have the repo:
  > sudo add-apt-repository ppa:gnome-terminator
  > sudo apt-get update
  > sudo apt-get install terminator

Setup:
- In preferences:
  > Infinite scrollback is selected
  > Profiles>colors>Change palette to "White on Black"
  > Profiles>Background>Solid Color

- Google Search Plugin:
https://github.com/msudgh/terminator-search

- Shortcuts
  - Ctrl + Shift + O = Virtual Split
  - Ctrl + Shift + E = Horizontal Split
  - Ctrl + Shift + Z = Maximizes a current tabbed window to full screen and then restores to tabbed by pressing again

- installing power line fonts:
  > sudo apt install fonts-powerline


- highlighting the syntax is found below:
https://github.com/zsh-users/zsh-syntax-highlighting


## How to Create/Enable Shared Folders in Kali 2020.x

- VMware Workstation Player (VMWP) with Windows 10 Professional or whatever works as host
- Kali Linux 2020.x as guest OS
-- Create the shared folder on the host, e.g.: E:\VM_SHARE
-- Start the guest.
-- From the VMWP :
````
Player
Manage
Virtual Machine Settings...
Options tab
Shared Folders
Always enabled
Add..., Next
Browse...
Host path : E:\VM_SHARE
Name : VM_SHARE
Next
Enable this share
Finish
OK
````
4 - create the folder:
`cd /mnt
sudo mkdir hgfs
`

5 - From the terminal window create (or add to) the file
`/etc/rc.local`
and then add the following line to it and save the file:
`#!/bin/sh -e
sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other`

6 - Make the file executable:
`sudo chown root /etc/rc.local
sudo chmod 755 /etc/rc.local`

Test `ls -l /etc/rc.local` to see if it is `-rwxr-xr-x` and it should be right.

7 - Restart the VM, and check whether the test file also appears on the guest Credits of this goes to this dude (https://unix.stackexchange.com/questions/594080/where-to-find-the-shared-folder-in-kali-linux) here.

# Change OllyDbg layout fonts to become readable:
Add the following lines to the *.ini file of OllyDbg v2.x to make it more readable or suitable for working with it:

`[Colour schemes]
Scheme name[4]=KuNgBiM's Scheme
Foreground_1[4]=*,*,808000,0,FFFF,80,*,FF00,*,FF0000,*,*,*,*,*,*
Foreground_2[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*
Background_1[4]=C0DCC0,C0DCC0,C0DCC0,FF00,*,FFFF00,*,*,C0DCC0,FFFF,*,*,*,*,*,*
Background_2[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*
Operands[4]=0
Modified commands[4]=0

[Highlighting schemes]
Scheme name[4]=KuNgBiM's Code
Foreground_1[4]=*,*,*,*,*,*,*,*,*,*,*,*,FF0000,FF,FF,FF0000
Foreground_2[4]=0,0,0,FF00,FF,FF,*,*,800000,0,0,800080,FF00FF,80,FF00FF,*
Background_1[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,FFFF,FFFF,*
Background_2[4]=FFFF00,FF00,*,FF,*,*,*,*,*,*,*,*,*,*,*,*
Operands[4]=1
Modified commands[4]=0

[Fonts]
Font name[5]=KuNgBiM's Fonts
Font data[5]=-12,0,400,0,0,0,134,1,49,0,0,0
Face name[5]=#65B0#5B8B#4F53`

Alternately you can go to the git repo of () to find the some of the theme's for debuggers.
