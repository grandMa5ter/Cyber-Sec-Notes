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

5. Make the file executable: `sudo chown root /etc/rc.local sudo chmod 755 /etc/rc.local` Test `ls -l /etc/rc.local` to see if it is `-rwxr-xr-x` and it should be right.
6. Restart the VM, and check whether the test file also appears on the guest Credits of this goes to this dude (<https://unix.stackexchange.com/questions/594080/where-to-find-the-shared-folder-in-kali-linux>) here.

**MacOS Users** If you are in MacOS host and using fusion and Kali 2020.x, then should pay a visit to the kali documentation [here](https://www.kali.org/docs/virtualization/install-vmware-guest-tools/).

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
