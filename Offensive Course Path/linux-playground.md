# Linux Playground

## Basics

### Linux Root Directory Structure

Below is a snapshot of linux directory structure which I found really useful at times.<br>
![Alt text](/Offensive%20Course%20Path/pics/linux.png?raw=true "LinuxTree")

### Linux list command

Below is a description of fields when we run the command `ls -l` or `ls -la`<br>
![Alt text](/Offensive%20Course%20Path/pics/linux%202.png?raw=true "Linuxlsfields")

### Linux ownership breakdown of files

Below is a high level overview of file ownership and translation of them.<br>
![Alt text](/Offensive%20Course%20Path/pics/linux%203.png?raw=true "Linuxdirectoryfields")

Typical Command line anatomy: ![Alt text](/Offensive%20Course%20Path/pics/command_anatomy.png?raw=true "Linuxanatomy")

### The system

- `id` know yourself
- `w` who is logged in (-f to find where they are logging in from)
- `lsblk` list block storage devices
- `lscpu` display info about the CPUs
- `lstopo` display hardware topology (need hwloc, hwloc-gui packages)
- `free` free and used memory (try free -g)
- `lsb_release -a` distribution info (sometimes not available)
- `uname -a` kernel information
- `which <cmdname>` to verify command is available **Use ctrl-c to kill stuck commands or long running ones**

### The Processes

- `ps -aux` lists the processes by name

  - Process differs in implementation (POSIX, GNU and BSD)
  - Determined by style of options: POSIX (-), GNU (--), BSD (no dash) before options

- `top`, `htop`, `atom` will Display processes

- Lower process priority by being nice and fly under the radar

  - `nice -n 19 tar cvzf archive.tgz large_dir`

- Kill a process: `kill <pid>`

  - to kill non-responsive processes
  - hung sessions

### Work with files

- cat for relatively short files `cat states.txt`
- `less` is more than `more` for long files `less /etc/ntp.conf`
- `tail -f` to watch a file growing live
- What can you do about binary files? (not much)

  - `strings` will print the printable strings of file
  - `od` will print file in octal format
  - `cmp` will compare them byte by byte

- Compare text files with

  - `comm` _sorted_ files line by line
  - `diff` differences line by line -- used most frequently, rich options set, see man

### Using Internet (CMD)

- curl is commonly used to download from the web:<br>
  `curl -O http://www.gutenberg.org/files/4300/4300-0.txt curl ifconfig.me #quickly find my IP`
- wget is similar:<br>
  `wget http://www.gutenberg.org/files/4300/4300-0.txt`<br>
  `wget https://kubernetespodcast.com/episodes/KPfGep{001..062}.mp3`
- lynx can be a useful text-based browser:

  - avoid pesky ads on the web
  - when internet is slow / only care about text eg. `lynx text.npr.org`
  - read local html pages, eg. those found in `/usr/share/doc`
  - `w3m` and `links` are other text-based browsers: `w3m lite.cnn.com`

### Comand Line Ninja: Navigation

MAC users: terminal pref > profile > keyboard settings > Use option as meta key

![Alt text](/Offensive%20Course%20Path/pics/cmd_ninja_nav.png?raw=true "LinuxCmdNavigation")<br>
`**ctrl-]<char> moves cursor to 1st occurrence of <char> to right</char></char>**`<br>
`**ctrl-alt-]<char> moves cursor to 1st occurrence of <char> to left</char></char>**`

### Command Line Ninja: Deletion

![Alt text](/Offensive%20Course%20Path/pics/cmd_ninja_del.png?raw=true "LinuxCmdDeletion")<br>
**use ctrl-y to paste back the deleted**

### Wild Cards

Wild cards are characters that expand at runtime:

- `*` expands to any number of characters:<br>
  `ls -lh /etc/*.conf #all items with .conf extension`
- `?` expands to one character:<br>
  `ls -ld ? ?? ??? #list items 1,2 or 3 chars long`
- Negation (!)<br>
  `ls -ld [!0-9]* #items that don't start with a number`
- Escaping and quoting<br>
  `\` for escaping a wildcard - - > prevent expansion `'` for quoting a wildcard - - > prevent expansion

### Trick and Treats - Useful

- `!!` repeats the last command
- `!$` change command, keep last argument:<br>
  `cat states.txt #file too long to fit screen` `less !$ #reopen it with less`
- `!*` change command, keep all arguments:<br>
  `head states.txt | grep '^Al' #should be tail` `tail !* #no need to type the rest of the command`
- `alt-. #paste last argument of previous command`
- `alt-<n>-alt-. #paste nth argument of previous command`

- `>x.txt #create an empty file / "zero" a large file`

- `lsof -P -i -n #apps using internet`<br>
  tag & later search hard-to-remember command from history

- `ctrl-l #clear terminal`

- `cd- #change to previous dir`
- `cd #change to homedir`
- `ctrl-r #recall from history`
- `ctrl-d #logout from terminal`

## Streams, Pips and Redirections

### Anatomy of a redirection using streams

![Alt text](/Offensive%20Course%20Path/pics/anatom_redirect.png?raw=true "AnatomyOfRedirection")<br>

### Terminal I/O Streams and Redirections

Three I/O streams on terminal: standard input (stdin), standard output (stdout) and standard error (stderr)

- Represented by "file descriptors" (think of them as ids): 0 for stdin, 1 for stdout, 2 for stderr
- Angle bracket notation used for redirect to/from commands/files: - > send stream to a file
- < receive stream from a file
- > > to append

- << to in-place append (used in "heredoc")
- <<< is used in "herestring" (not covering today)
- & is used to "write into" a stream, eg. &1 to write into stdout
- Send stdout and stderr to same file: pip install rtv > stdouterr.txt 2>&1 ac -pd &> stdouterr.txt #short form (bash v4+)
- Disregard both stdout and stderr: wget imgs.xkcd.com/comics/command_line_fu.png &> /dev/null #/dev/null is a "null" file to discard streams
- Read from stdin as output of a command diff <(ls dirA) <(ls dirB)
- Append stdout to a log file: sudo yum -y update >> yum_update.log

### The pipe

A pipe is a Linux concept that automates redirecting the output of one command as input to a next command.

- Use of pipe leads to powerful combinations of independent commands. eg.:

  ```
  find .| less #read long list of files page wise
  head prose.txt | grep -i 'little'
  echo $PATH | tr ':' '\n' #translate : to newline
  history | tail #last 10 commands
  free -m|grep Mem:|awk '{print $4}' #available memory
  du -s *|sort -n|tail #10 biggest files/dirs in pwd
  ```

#### Demystifying and debugging piped commands

`free -m|grep Mem:|awk '{print $4}'` is equivalent to running the following 4 commands:

```
free -m > tmp1.txt`
grep Mem: tmp1.txt > tmp2.txt
awk '{print $4}' tmp2.txt
rm tmp1.txt tmp2.txt
```

Reducing the piped stages is often efficient and easier to debug. For instance, the above pipeline may be reduced like so: `free -m|awk '/Mem:/{print $4}' #more on awk later`

#### More Examples

```
#get pdf of a man page
man -t diff | ps2pdf - diffhelp.pdf

#get today's files
ls -al --time-style=+%D | grep `date +%D`

#top 10 most frequently used commands
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head
```

### Commands that only accept literal args

Most commands receive input from stdin (so, pipe) and file, eg.

- `wc < states.txt` **#ok**
- `wc states.txt` **#ok**
- There are some exceptions though
- Some receive input only from stdin and not from file, eg.

  - `tr 'N' 'n’ states.txt` #(strangely) **NOT OK**
  - `tr 'N' 'n’ < states.txt` **#ok**

- Some receive input neither from stdin nor from file, eg.
- `echo < states.txt` **#NOT OK** _(assuming want to print file contents)_
- `echo states.txt` **#NOT OK** _(assuming want to print file contents)_
- `echo "Hello miss, howdy? "` **#ok, takes literal args**
- `cp`, `touch`, `rm`, `chmod` are other examples

### xargs: When pipe is not enough!

- Some commands do not read from standard input, pipe or file; they need arguments
- Additionally, some systems limit on number of arguments on command line

  - for example: `rm tmpdir/*.log` will fail if there are too many `.log` files

- xargs fixes both problems

  - Converts standard input to commands into literal args
  - Partitions the args to a permitted number and runs the command over them repeatedly

- For instance, create files with names on the `somelist.txt` file:
- `xargs touch < somelist.txt`

### GNU Parallel

- Run tasks in parallel from command-line
- Similar to xargs in syntax
- Treats parameters as independent arguments to command and runs command on them in parallel
- Synchronized output -- as if commands were run sequentially
- Configurable number of parallel jobs
- Well suited to run simple commands or scripts on compute nodes to leverage multicore architectures
- May need to install as not available by default: (<http://www.gnu.org/software/parallel>)
- Find all html files and move them to a directory<br>
  `find . -name '*.html' | parallel mv {} web/`
- Delete pict0000.jpg to pict9999.jpg files (16 parallel jobs)<br>
  `seq -w 0 9999 | parallel -j 16 rm pict{}.jpg`
- Create thumbnails for all picture files (imagemagick software needed)<br>
  `ls *.jpg | parallel convert -geometry 120 {} thumb_{}`
- Download from a list of urls and report failed downloads<br>
  `cat urlfile | parallel "wget {} 2>errors.txt"`

_Some of Material Belongs to to "Ketan M. (km0@ornl.gov)"_<br>
_Some of material I gathered I can't remember for where; If you it was you, let me know and I buy you a beer_
