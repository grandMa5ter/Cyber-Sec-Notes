# Generic Setup

## How to install python 2 on Kali 2020.x onwards:

download the bloody get-pip.py from here:

```shell
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
pip install --upgrade setuptools
sudo pip install --upgrade setuptools
sudo pip2 install #[py 2 package]
```

## Setting up the terminator for Kali 2020.x onwards

> sudo apt install terminator
Or if they don't have the repo:
> sudo add-apt-repository ppa:gnome-terminator sudo apt-get update sudo apt-get install terminator

Setup:

- In preferences:
  > Infinite scrollback is selected Profiles>colors>Change palette to "White on Black" Profiles>Background>Solid Color
- Google Search Plugin: <https://github.com/msudgh/terminator-search>
- Shortcuts
  - Ctrl + Shift + O = Virtual Split
  - Ctrl + Shift + E = Horizontal Split
  - Ctrl + Shift + Z = Maximizes a current tabbed window to full screen and then restores to tabbed by pressing again

- installing power line fonts:

  > sudo apt install fonts-powerline

- highlighting the syntax is found below: <https://github.com/zsh-users/zsh-syntax-highlighting>

## How to Create/Enable Shared Folders in Kali 2020.x

- VMware Workstation Player (VMWP) with Windows 10 Professional or whatever works as host
- Kali Linux 2020.x as guest OS -- Create the shared folder on the host, e.g.: E:\VM_SHARE -- Start the guest. -- From the VMWP :

  ```text
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
  ```

4 - create the folder: `cd /mnt sudo mkdir hgfs` 5 - From the terminal window create (or add to) the file `/etc/rc.local` and then add the following line to it and save the file: `#!/bin/sh -e sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other` 6 - Make the file executable: `sudo chown root /etc/rc.local sudo chmod 755 /etc/rc.local` Test `ls -l /etc/rc.local` to see if it is `-rwxr-xr-x` and it should be right. 7 - Restart the VM, and check whether the test file also appears on the guest Credits of this goes to this dude (<https://unix.stackexchange.com/questions/594080/where-to-find-the-shared-folder-in-kali-linux>) here.

## Curropt ZSH History files

Sometimes the zsh gives an error of curropt file and it drives me nuts. Below is a way to fix it. Credit to George for this beautifull script to fx it.

```shell
#!/usr/bin/env zsh
# George Ornbo (shapeshed) http://shapeshed.com
# Fixes a corrupt .zsh_history file
mv ~/.zsh_history ~/.zsh_history_bad
strings -eS ~/.zsh_history_bad > ~/.zsh_history
fc -R ~/.zsh_history
rm ~/.zsh_history_bad
```

## AutoRecon

**The following setups stuff for pipx and all the necessary things associated to "AutoRecon" tool.** This is what I have done on Kali 2020.x to get it working: Make sure to run usual `sudo apt-get update && upgrade -y` first.

1 - Install the prerequisits of AutoRecon:
  `sudo apt install seclists curl enum4linux ffuf gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf` 
2 - Then you can move to installing pipx or you can use pip. Whatever you fancy:
3 - Install the pipx first: `python3 -m pip install --user pipx`
4 - Put this pipx into our bash rc path: `python3 -m pipx ensurepath` 
  Rest of steps is about making sure the autocomplete on pipx is up and running:
5 - This is to add autocomplete to zsh and not bash: `autoload -U bashcompinit`
6 - run: `bashcompinit`
7 - And lastly run: `eval "$(register-python-argcomplete pipx)"`
Then when all that is done. DO: `pipx install git+https://github.com/Tib3rius/AutoRecon.git`
