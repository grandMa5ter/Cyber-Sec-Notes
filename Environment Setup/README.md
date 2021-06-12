# How to install python 2 on Kali 2020.x onwards:

download the bloody get-pip.py from here:

```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
pip install --upgrade setuptools
sudo pip install --upgrade setuptools
sudo pip2 install #[py 2 package]
```

# Setting up the terminator for Kali 2020.x onwards:

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

# How to Create/Enable Shared Folders in Kali 2020.x

- VMware Workstation Player (VMWP) with Windows 10 Professional or whatever works as host
- Kali Linux 2020.x as guest OS -- Create the shared folder on the host, e.g.: E:\VM_SHARE -- Start the guest. -- From the VMWP :

  ```
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

# Curropt ZSH History files

Sometimes the zsh gives an error of curropt file and it drives me nuts. Below is a way to fix it. Credit to George for this beautifull script to fx it.

```
#!/usr/bin/env zsh
# George Ornbo (shapeshed) http://shapeshed.com
# Fixes a corrupt .zsh_history file

mv ~/.zsh_history ~/.zsh_history_bad
strings -eS ~/.zsh_history_bad > ~/.zsh_history
fc -R ~/.zsh_history
rm ~/.zsh_history_bad
`
```

# making sure that vulscan in script of NSE for nmap is up to date and also working, comes in handy for enumeration

`cd /usr/share/nmap/scripts/` `sudo git clone https://github.com/vulnersCom/nmap-vulners.git` `sudo git clone https://github.com/scipag/vulscan.git` double check they are there: `ls vulscan/*.csv` To ensure that the databases are fully up to date, we can use the updateFiles.sh script found in the vulscan/utilities/updater/ directory. `cd vulscan/utilities/updater/` `sudo chmod +x updateFiles.sh` We can then execute and run the script by entering the below command into our terminal:`sudo ./updateFiles.sh` Above would not work if you don't do the following, somehow nmap cannot find its script. So:

```
cd /usr/share/nmap/scripts
sudo git clone https://github.com/scipag/vulscan scipag_vulscan
sudo ln -s pwd/scipag_vulscan /usr/share/nmap/scripts/vulscan
cd scipag_vulscan
sudo cp vulscan.nse /usr/share/nmap/scripts
sudo nmap --script-updatedb
```

done, tadaaa! Below are the usefull command that you can run and nmap gives you lots of goodies:

```
nmap --script nmap-vulners -sV -p# ###.###.###.###
nmap --script vulscan -sV -p# ###.###.###.###
nmap --script vulscan --script-args vulscandb=database_name -sV -p# ###.###.###.###
nmap --script vulscan --script-args vulscandb=scipvuldb.csv -sV -p# ###.###.###.###
nmap --script vulscan --script-args vulscandb=exploitdb.csv -sV -p# ###.###.###.###
nmap --script vulscan --script-args vulscandb=securitytracker.csv -sV -p# ###.###.###.###
nmap --script vulscan --script-args vulscandb=exploitdb.csv -sV -p22 1##.##.###.#43
nmap --script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sV -p# ###.###.###.###
```

## AutoRecon

**The following setups stuff for pipx and all the necessary things associated to "AutoRecon" tool.** This is what I have done on Kali 2020.x to get it working: Make sure to run usual `sudo apt-get update && upgrade -y` first.

1. Install the prerequisits of AutoRecon:

  - `sudo apt install seclists curl enum4linux ffuf gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf` Then you can move to installing pipx or you can use pip. Whatever you fancy:

2. Install the pipx first: `python3 -m pip install --user pipx`

3. Put this pipx into our bash rc path: `python3 -m pipx ensurepath` Rest of steps is about making sure the autocomplete on pipx is up and running:
4. This is to add autocomplete to zsh and not bash: `autoload -U bashcompinit`
5. run: `bashcompinit`
6. And lastly run: `eval "$(register-python-argcomplete pipx)"`

Then when all that is done. DO: `pipx install git+https://github.com/Tib3rius/AutoRecon.git`
