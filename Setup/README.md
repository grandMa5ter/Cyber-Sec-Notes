- [Generic Setup](#generic-setup)
  - [Terminator Setup and quick reminder](#terminator-setup-and-quick-reminder)
    - [Terminator Shortcuts](#terminator-shortcuts)
  - [How to install python 2 on Kali 2020.x onwards](#how-to-install-python-2-on-kali-2020x-onwards)
  - [Setting up the terminator for Kali 2020.x onwards](#setting-up-the-terminator-for-kali-2020x-onwards)
  - [Powershell/Commandline Windows up/down arrow doesn't work in Kali?](#powershellcommandline-windows-updown-arrow-doesnt-work-in-kali)
  - [How to Create/Enable Shared Folders in Kali 2020.x](#how-to-createenable-shared-folders-in-kali-2020x)
    - [Clipboard and Shared folder Still Not Working](#clipboard-and-shared-folder-still-not-working)
  - [Installing VSCoidum on Debian](#installing-vscoidum-on-debian)
    - [Colour coded test files:](#colour-coded-test-files)
  - [Curropt ZSH History files](#curropt-zsh-history-files)
  - [Customise ZSHRC to some coolish style](#customise-zshrc-to-some-coolish-style)
  - [Oh-MY-ZSH IS COOL](#oh-my-zsh-is-cool)
  - [AutoRecon](#autorecon)
  - [Docker Images](#docker-images)
    - [Other commands](#other-commands)
    - [Docker on Kali](#docker-on-kali)
    - [Docker on MacOS](#docker-on-macos)
  - [Empire or any other tool with Docker](#empire-or-any-other-tool-with-docker)
  - [Go Language on Kali](#go-language-on-kali)
    - [Getting packages with go](#getting-packages-with-go)
  - [Easy OpenVPN](#easy-openvpn)
  - [Useful tools](#useful-tools)
    - [Tools installed](#tools-installed)
    - [Additional tools](#additional-tools)

# Generic Setup

## Terminator Setup and quick reminder

I used Tmux and had watched videos of ippsec setting up his tmux. I feel more comfortable with terminator that tmux tbh.

```text
Infinite scrollback is selected
Profiles>colors>Change palette to "White on Black"
Profiles>Background>Solid Color
```

- Google Search plugin: <https://github.com/msudgh/terminator-search>

### Terminator Shortcuts

```text
Ctrl + Shift + O = Virtual Split
Ctrl + Shift + E = Horizontal Split

Ctrl + Shift + Z = Maximizes a current tabbed window to full screen and then restores to tabbed by pressing again
Ctrl + Shift + T = Opens a new tab

Ctrl + Shift + C = Copy to clipboard
Ctrl + Shift + V = Paste
```

## How to install python 2 on Kali 2020.x onwards

download the bloody get-pip.py from here:

```shell
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
pip install --upgrade setuptools
sudo pip install --upgrade setuptools
sudo pip2 install #[py 2 package]
```

- Also double check python3 pip install as well: `sudo apt install python3-pip`

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

## Powershell/Commandline Windows up/down arrow doesn't work in Kali?

- Download the rlwrap within the kali via: `sudo apt-get install rlwrap`
- And then before going into the reverse shell execute `script reverse.log`
- Then when spawning the reverse shell: `rlwrap nc -nvlp 9001`

## How to Create/Enable Shared Folders in Kali 2020.x

1. VMware Workstation Player (VMWP) with Windows 10 Professional or whatever works as host
2. Kali Linux 2020.x as guest OS -- Create the shared folder on the host, e.g.: E:\VM_SHARE -- Start the guest. -- From the VMWP :

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

3. create the folder: `cd /mnt sudo mkdir hgfs`
4. From the terminal window create (or add to) the file `/etc/rc.local` and then add the following line to it and save the file:

   ```shell
   #!/bin/sh -e 
   sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
   ```

5. Make the file executable:
  `sudo chown root /etc/rc.local`
and
  `sudo chmod 755 /etc/rc.local`
6. Test `ls -l /etc/rc.local` to see if it is `-rwxr-xr-x` and it should be right.
7. Restart the VM, and check whether the test file also appears on the guest Credits of this goes to this dude (<https://unix.stackexchange.com/questions/594080/where-to-find-the-shared-folder-in-kali-linux>) here.

**MacOS Users** If you are in MacOS host and using fusion and Kali 2020.x, then should pay a visit to the kali documentation [here](https://www.kali.org/docs/virtualization/install-vmware-guest-tools/).

### Clipboard and Shared folder Still Not Working

You want to force a manual reinstall of open-vm-tools (as something has gone wrong):
  `sudo apt update`
and do a reinstall of vmware tools:
  `sudo apt install -y --reinstall open-vm-tools-desktop fuse`
and do a reboot of VM: `sudo reboot -f`

You need to sometimes add Support for Shared Folders When Using OVT. Unfortunately, shared folders will not work out of the box, some additional scripts are needed. Those can be installed easily with `kali-tweaks`.

In the Kali Tweaks menu, select _Virtualization_, then _Install additional packages and scripts for VMware_. Congratulations, you now have two additional tools in your toolbox!
The first one is a little script to mount the VMware Shared Folders. Invoke it with:
  `sudo mount-shared-folders`
And with a bit of luck, checking /mnt/hgfs/ you should see your shared folders.
The second script is a helper to restart the VM tools. Indeed, it’s not uncommon for OVT to stops functioning correctly (e.g. such as copy/paste between the host OS and guest VM stops working). In this case, running this script can help to fix the issues:
  `sudo restart-vm-tools`
  
*This has worked in Kali 2020.x onwards and Parrot OS. Other Debian I haven't tried!*

## Installing VSCoidum on Debian

1 - Add the GPG key to repo so that updates with future update commands:
  `wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg`

2 - Add the repository to our repository list:
  `echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list`

3 - And then do an update based on repositories and install:
  `sudo apt update && sudo apt install codium`

### Colour coded test files:

- Press `Ctrl P` and run the command: `ext install xshrim.txt-syntax`
- Python exploits sometimes they are not formatted correctly. Hold `Ctrl Shift and i` to correct the formatting it.
- Install [Cheat.sh](https://marketplace.visualstudio.com/items?itemName=vscode-snippet.Snippet) for code snippets into vscode
  - Then highlight a sentence, do `Ctrl Shift S` to search for cheatsheets!

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

## Customise ZSHRC to some coolish style

1- Change the history size and set some operations:

```shell
# History configurations
HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=10000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
setopt hist_verify            # show command with history expansion to user before running it
#setopt share_history         # share command history data
setopt appendhistory
```

2 - Add the following to the bottom of your zshrc file:

```shell
#####################################################
# Making Kali Command Prompts beautifull again! 
# Stole all this from https://github.com/theGuildHall/pwnbox

# Prompt
if [[ $(/opt/vpnbash.sh) == *.10.* ]]; then PROMPT="%F{red}┌[%f%F{green}%D{$(/opt/vpnserver.sh)}$(/opt/vpnbash.sh)%f%F{red}]─[%B%F{%(#.red.blue)}%n%(#.💀.㉿)%m%b%F{%(#.blue.red)}]─[%f%F{magenta}%d%f%F{red}]%f"$'\n'"%F{red}└╼%f%F{green}[%f%F{yellow}★%f]%f%F{yellow}$%f";else PROMPT="%F{red}┌[%B%F{%(#.red.blue)}%n%(#.💀.㉿)%m%b%F{%(#.blue.red)}]─[%f%F{magenta}%d%f%F{red}]%f"$'\n'"%F{red}└╼%f%F{green}[%f%F{yellow}★%f]%f%F{yellow}$%f";fi

# Auto completion / suggestion
# Mixing zsh-autocomplete and zsh-autosuggestions
# Requires: zsh-autocomplete (custom packaging by Parrot Team)
# Jobs: suggest files / foldername / histsory bellow the prompt
# Requires: zsh-autosuggestions (packaging by Debian Team)
# Jobs: Fish-like suggestion for command history
source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
#source /usr/share/zsh-autocomplete/zsh-autocomplete.plugin.zsh
# Select all suggestion instead of top on result only
zstyle ':autocomplete:tab:*' insert-unambiguous yes
zstyle ':autocomplete:tab:*' widget-style menu-select
zstyle ':autocomplete:*' min-input 2
bindkey $key[Up] up-line-or-history
bindkey $key[Down] down-line-or-history

# Useful alias for benchmarking programs
# require install package "time" sudo apt install time
alias time="/usr/bin/time -f '\t%E real,\t%U user,\t%S sys,\t%K amem,\t%M mmem'"
# Display last command interminal
echo -en "\e]2;Kali Terminal\a"
preexec () { print -Pn "\e]0;$1 - Kali Terminal\a" }
```

3 - Create a `vpnbash.sh` file under `/opt/vpnbash.sh` and put the following within it:

  ```shell
  #!/bin/bash
  htbip=$(ip addr | grep tun0 | grep inet | grep 10. | tr -s " " | cut -d " " -f 3 | cut -d "/" -f 1)

  if [[ $htbip == *"10."* ]]
  then
    echo "-%B%F{%(#.red.blue)}$htbip%b%F{%(#.blue.green)}"
  else
    echo ""
  fi
  ```

4 - Create a `vpnserver.sh` file under `/opt/vpnserver.sh` as well with the following content:

  ```shell
  #!/bin/bash

  #cat /etc/openvpn/*.conf | grep "remote " | cut -d " " -f 2 | cut -d "." -f 1 | cut -d "-" -f 2-

  vpn=$(cat `systemctl status openvpn@* | grep "/usr/sbin/openvpn" | tr -s " " | cut -d " " -f 12` | grep "remote " | cut -d " " -f 2)

  if [[ $vpn == *"hackthebox"* ]]
  then
      cat `systemctl status openvpn@* | grep "/usr/sbin/openvpn" | tr -s " " | cut -d " " -f 12` | grep "remote " | cut -d " " -f 2 | cut -d "." -f 1 | cut -d "-" -f 2-
  else
      cat `systemctl status openvpn@* | grep "/usr/sbin/openvpn" | tr -s " " | cut -d " " -f 12` | grep "remote " | cut -d " " -f 2
  fi
  ```

5 - From now on, when you add open vpn files to your `/etc/openvpn/[your vpn file]` and connect to vpn they will be shown in your terminal:
  `sudo cp [your VPN FILE].ovpn /etc/openvpn/`
and 
  `sudo mv /etc/openvpn/[your VPN file].ovpn /etc/openvpn/[your VPN file].conf` after that you can start your openvpn normally same as usual.

## Oh-MY-ZSH IS COOL

After I worked around with zsh, I thought I want much more coolish look and feel. Therefore, I went and installed oh-my-zsh:
1 - Install Oh-my-zsh via wget: `sh -c "$(wget https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"`
2 - Install the Powerline font to spice up your CLI with icons: `sudo apt install fonts-powerline`
3 - Change themes to "agnoster" by finding the `ZSH_THEME` variable(inside *.zshrc*) and changing it:`ZSH_THEME="agnoster"`.
4 - I don’t like it that the theme shows git. To get rid of this, we change the directory to `cd ~/.oh-my-zsh/themes`.
  4.1 - Now we can change the ‘Main prompt’. We don’t need to prompt_context in the function build_prompt(). Just comment out this line or remove it. At last, change the PROMPT variable to $(build_prompt).
5 - To actually see the theme, you have to source your *.zshrc* file like this: `source ~/.zshrc`; usually it is already enabled within *.zshrc* file.
6 - Add *zsh-syntax-highlighting* to the plugins list. Navigate to `~/.oh-my-zsh/custom/plugins` and clone the code from Github into this folder: `git clone https://github.com/zsh-users/zsh-syntax-highlighting`
7 - Add *zsh-autosuggestions* to the plugins list by cloning the code into the same folder as before and `git clone https://github.com/zsh-users/zsh-autosuggestions`
8 - After all that, edit or change the *.zshrc* file `plugins` section to contain: `plugins=(git colored-man-pages zsh-syntax-highlighting zsh-autosuggestions)`.

9 - Do below if you want to be brave:
  ```shell
  #Installing Powerlevel10k theme on oh-my-zsh
  cd .oh-my-zsh/custom/themes
  git clone --depth=1 https://github.com/romkatv/powerlevel10k.git
  #edit the .zshrc file
  ZSH_THEME="powerlevel10k/powerlevel10k"
  #exit the terminal and restart the terminal, go through config as you see fit.
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

## Docker Images

It is really nice to see some tools and OSes are being ported within docker space as a way of fast pulling up enviornments to do something quickly and trying small stuff then getting rid of it. Extremely powerfull things happening in docker space. So, Parrot OS has its own docker. I guess below is a quick guide on how to pull it down and run with quick short commands that should come handy:

- Pulling it down from repository:
  `docker pull parrotsec/security`
  `docker pull parrotsec/core`

- Running parrot in docker(I map my local /Users/kev to a folder called "HostFolder" in container):
  `docker run --rm -it --network host -v $PWD:/HostFolder parrotsec/security`

- or just run it with a name:
  `docker run --name sec-1 -ti parrotsec/security`

### Other commands

- Stop the container:
  `docker stop pcore-1`
- Resume a previously-stopped container:
  `docker start pcore-1`
- Remove a container after use:
  `docker rm pcore-1`
- List all the instantiated containers:
  `docker ps -a`  
- Start a container and automatically remove it on exit:
  `docker run --rm -ti parrotsec/core`
- Open a port from the container to the host
  `docker run --rm -p 8080:80 -ti parrotsec/core`
- The docker system prune command removes all stopped containers, dangling images, and unused networks:

  ```shell
  docker container ls -a --filter status=exited --filter status=created #get a list of all non-running (stopped) containers that will be removed with docker container prune
  docker container prune --filter "until=12h" # prune command allows you to remove containers based on a certain condition
  docker system prune
  docker system prune -a
  docker system prune --volumes
  ```

- To remove one or more Docker containers, use the docker container rm command, followed by the IDs of the containers you want to remove:

  ```shell
  docker container ls -a
  docker container rm cc3f2ff51cab cd20b396a061
  docker rm $(docker ps -qa) #Remove all the containers
  ```

- To stop all running containers, enter the docker container stop command
  `docker container stop $(docker container ls -aq)`
- Listing all the docker images available on the system:

  ```shell
  docker image ls
  docker image prune #can be used to remove dangled and unused images
  docker image prune -a #can be used to remove all dangled and unused images
  docker image prune -a --filter "until=12h" #remove images based on a particular condition with the –filter option.
  ```

### Docker on Kali

Remember that docker on kali is named=docker.io so for installing it:
  `sudo apt-get install docker.io`

- And then you need to start it:
  `sudo systemctl enable docker --now`
- You can now get started with using docker, with sudo. If you want to add yourself to the docker group to use docker without sudo, an additional step is needed:
  `sudo usermod -aG docker $USER`
- Other commands to understand and restart docker:
  `sudo service docker status`

  `sudo systemctl start docker`

### Docker on MacOS

If you looking for installing docker on MacBook, I found below instruction is pretty straight forward and didn't need a lot of thinkering and was straigh forward:

1 - First, You need install docker from brew with

  ```zsh
  brew update
  brew install docker
  ```

2 - install virtualbox and docker-machine, because of the linux native environment on docker:

  ```zsh
  brew install docker-machine
  brew install virtualbox # check your MacOS’ System Preference and verify if System software from developer “Oracle America, inc” was blocked from loading shows up. If you see it, hit the “Allow”-button and install it again
  ```

**Note: If above didn't work and still allowing the app didn't work like mine; do reset virtual box configuration in mac with sudo "/Library/Application Support/VirtualBox/LaunchDaemons/VirtualBoxStartup.sh" restart.**

3 - Create an engine for docker by:
  `docker-machine create --driver virtualbox default`

4 - Run this: `docker-machine ls` and you should see something like:

  ```shell
  docker-machine ls
  NAME      ACTIVE   DRIVER       STATE     URL                         SWARM   DOCKER      ERRORS
  default   *        virtualbox   Running   tcp://192.168.99.100:2376           v19.03.12
  ```

This means the virtual environment in background is running for docker to work in MacOS.

5 - finally, you need to run below command:
  `docker-machine env default`

6 - and the step 5 command tells you run below command:
  `eval $(docker-machine env default)`

**Check if everything works by `docker run hello-world` and should tell you all us okay**

## Empire or any other tool with Docker

If you ever needed to run Empire, you can always run it through docker. The steps are simply below or mentioned within [docker image of empire](https://hub.docker.com/r/empireproject/empire/dockerfile):

1. `sudo docker create -v /opt/Empire --name data empireproject/empire`
2. `sudo docker run -ti --volumes-from data empireproject/empire /bin/bash`
3. Go to the empire folder and run `/setup/install.sh` to install empire properly and build all the requirements.

## Go Language on Kali

1 - In order to use packages that utilise go lang we need to install go lang on our system:
  `sudo apt-get install golang`
2 - Then we need to add the go to our path variable: `export GOPATH=/root/go` but just make sure that that directory exists: `sudo mkdir /root/go`.
3 - Also we need to create user local go directory for go as well with `mkdir /usr/local/go` and also create a path variable for it: `export GOROOT=/usr/local/go`
4 - Then we only need to add all to kali path variable as well: `PATH=$PATH:$GOROOT/bin/:$GOPATH/bin`

### Getting packages with go

Now that you have go installed and setup, if you want to get a repository that is with go, all you have to do is pull down the git reporisotry:
  `sudo git clone https://github.com/OJ/gobuster.git`
and then run:
  `sudo go run main.go`

Somethimes go will tell you that it needs additional modules and their path as well. If that happens, you can get those modules via; this will always pull them down in your go path as well:
  `go get github.com/satori/go.uuid`

From here on, you can always do `sudo go run main.go` but sometimes, it is easier to compile it and the run it:
  `sudo go build`
and this would gives us a nice executable and you can run the binary: `gobuster`

Interesting thing is gobuster can do **dir** as well as **dns**:
  `gobuster dir -u 10.10.10.24 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x php -t 50`
and
  `gobuster dns -d google.com -w ~/wordlists/subdomains.txt`

## Easy OpenVPN

In order to connect to the lab environment when you boot up your HTB or THM pen testing boxes, do the following which is easier:

1. Download your *.ovpn files and do copy them into openVPN directory `sudo mv ~/Download/<name_of_VPN_file>.ovpn /etc/openvpn/<name_of_VPN_file>.conf`
2. Then create a*.conf file out of it as well: `sudo mv ~/Downloads/<name_of_VPN_file>.ovpn /etc/openvpn/<name_of_VPN_file>.conf`
3. Start the vpn service with: `sudo service openvpn start`
4. Stop the service naturally with: `sudo service openvpn stop`
5. If by any chance, you have another VPN file that doesn't have autologin and needs a user/pass:
   1. Put username/password in separate line in file(1st line username and 2nd line password) such as `sudo nano /etc/openvpn/auth.txt`
   2. Then make it readonly: `sudo chmod 400 /etc/openvpn/auth.txt`
6. Edit the config file such as `sudo nano /etc/openvpn/<name_of_VPN_file>.conf`; and go the line that has **auth-user-pass** to be **auth-user-pass /etc/openvpn/auth.txt** and save and exit.
7. If by anychance you wanted to do some diagnostic of OpenVPN and look at log files go to: `sudo grep ovpn /var/log/syslog`

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