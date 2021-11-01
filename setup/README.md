# Generic Setup

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

## Installing VSCoidum on Debian

1 - Add the GPG key to repo so that updates with future update commands:
  `wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg`

2 - Add the repository to our repository list:
  `echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list`

3 - And then do an update based on repositories and install:
  `sudo apt update && sudo apt install codium`

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
if [[ $(/opt/vpnbash.sh) == *.10.* ]]; then PROMPT="%F{red}┌[%f%F{green}%D{$(/opt/vpnserver.sh)}%f%F{red}]─[%f%F{green}%D{$(/opt/vpnbash.sh)}%f%F{red}][%B%F{%(#.red.blue)}%n%(#.💀.㉿)%m%b%F{%(#.blue.red)}]─[%f%F{magenta}%d%f%F{red}]%f"$'\n'"%F{red}└╼%f%F{green}[%f%F{yellow}★%f]%f%F{yellow}$%f" ;else PROMPT="%F{red}┌[%B%F{%(#.red.blue)}%n%(#.💀.㉿)%m%b%F{%(#.blue.red)}]─[%f%F{magenta}%d%f%F{red}]%f"$'\n'"%F{red}└╼%f%F{green}[%f%F{yellow}★%f]%f%F{yellow}$%f" ;fi

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
   echo "$htbip"
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
and `sudo mv /etc/openvpn/[your VPN file].ovpn /etc/openvpn/[your VPN file].conf` after that you can start your openvpn normally same as usual.

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
