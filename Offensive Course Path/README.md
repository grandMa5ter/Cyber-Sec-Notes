# OSCP Notes

Before I forget things and get amnesia, at least I have a copy here. And remember not all these notes are mine and I have gathered them here because I was wandering around and reading things. **Ofcourse I haven't done this. All credit would go @TjNull for his updated blog and thorough analysis.**

OSCP Preparation Boxes is in the [excel files](/Offensive%20Course%20Path/NetSecFocus%20Trophy%20Room.xlsx)

Also for enumeration of CTF boxes, you can refer to:

- [Generic](/Offensive%20Course%20Path/enumeration.md)
- [Linux](/Offensive%20Course%20Path/enumeration-linux.md)
- [Windows](/Offensive%20Course%20Path/enumeration-windows.md)

Also refer to [Linux Playground](/Offensive%20Course%20Path/linux-playground.md) for all linux interesting commands and operations.

## Dorks that would aid enumeration and exploitation

### Google Dorks

```
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

<https://github.com/swisskyrepo/PayloadsAllTheThings/search?q=TERM><br>
<https://twitter.com/search?q=TERM&src=typed_query><br>
<https://github.com/search?q=TERM><br>

## Using AutoRecon

The damn tool has lots of capability that I'm baffled why I didn't find it sooner. Jeez! So much time I have wasted with multiple windows and multiple codes and wait for hours to get results back. @Tib3rius hats off to you sir. Anywhere anytime, your beer is on me mate :)

Simple example: `autorecon $IP`

1. By default, AutoRecon will scan 5 target hosts at the same time but that number can be toggled using the -ct parameter. This is basically the number of targets getting scanned at the same time.

2. "-t" Space-separated list of either IP Addresses or CIDR Notations or even resolvable hostnames. We can also create a file with the targets in it. It should be in the format of one per new line.

  ```
  cat target.txt
  autorecon -t targets.txt
  ```

3. "-cs" which is the Concurrent Scans. This is basically the number of scans that are being performed per target. By default, the setting is set to 10\. When changed to any other value such as 2 then only 2 scans will be performed per host. Once it is finished it will run another instance of the scan. `autorecon -cs 5 $IP`

4. The –single-target argument enables the users to scan the host but changing the directory structure. It means that the AutoRecon will only scan the target but no directory will be created for that particular target. `autorecon $IP --single-target` `ls -la results` `cat results/report/notes.txt`

5. The –heartbeat argument allows the users to configure the duration of the updates that are provided by AutoRecon. By default, it is 60 seconds. `autorecon $IP --heartbeat 120` - - > Every 120 seconds!

6. Arguments:

  - we can either replace our own parameters instead of the ones that are provided here, by using the –nmap argument and passing the parameters that we want to perform. `autorecon $IP --nmap sV`
  - We can use the –nmap-append option to add our parameters but not override the AutoRecon default parameters. It will append our parameters to it. `autorecon $IP --nmap-append sS`

7. AutoRecon has different levels of verbosity. By default, it doesn't run with any verbosity that means it just informs the user when it initiates a scan and when the scan finishes, it does not provide any details regarding those tasks.

  - Verbose: `autorecon -v $IP`
  - Very Verbose: `autorecon -vv $IP`

8. creates a bunch of directories based on the type of evidence it collects. But there are some situations where all that is required is the scan results. This is where the Only Scans Dir argument comes into action. This prevents the creation of other directories. `autorecon $IP --only-scans-dir`

9. when initiated with a scan, it creates a result directory. The name of the directory can be configured using the -o parameter. If no parameter is mentioned, it will create the results directory in the current folder. Inside the results directory, it will divide into the different targets.

  ```
  ls -la | grep results
  cd results
  cd $IP
  tree
  ```

  Then you can the notes inside the folders: `cat ~/results/$IP/report/notes.txt` Full nmap report: `cat ~/results/192.168.126.132/scans/_full_tcp_nmap.txt`

10. It also runs the Enum4Linux scan upon detecting the operating system like Linux. The result for this scan is located at the following location: `results/<targetname>/scans/enum4linux.txt`

## Usefull Stuff during CTFs:

Below are the commands that are used rarely and there are lots of writeups but I usually forget. So I put them here for my reference and they come in handy:

1. We broke out of Jail? But shit shell? With python: `python -c 'import pty; pty.spawn("/bin/bash")'` Without python: `/usr/bin/script -qc /bin/bash /dev/null` Ctrl+z=`^z` you can examin current terminal with `echo $TERM` which should give you `xterm-256color` or something like that. Then `stty -a` should give you size of TTY="rows 38;column 116". **have that in mind the command looks strange and you can't see it**

  ### Normal Terminal

  In Kali: `stty raw -echo` `fg` In reverse shell: `reset` `export SHELL=bash` `export TERM=xterm256-color` `stty rows 38 columns 116`

### For ZSH shell

In Kali: `stty raw -echo; fg` In reverse shell: `stty rows $ROWS cols $COLS` `export TERM=xterm-256color` `exec /bin/bash`
