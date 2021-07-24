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

- `which` command

  - It searches through the directories defined in the `$PATH`
  - If a match is found, `which` returns its full paths `which sbd`

- `locate` command

  - quickest way to find location of directories or files
  - it searches a built-in database called `locate.db`
  - This databse is automatically updated by cron scheduler
  - Manual update of this db: `sudo updatedb`

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

- `!<num>` executes the line number from history (i.e. `!2` executes second line in history)
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

- `ctrl-r #recall from history` type a letter while holding the ctl+r and it searches history for that command.

- `ctrl-d #logout from terminal`

## Streams, Pips and Redirections

### Anatomy of a redirection using streams

![Alt text](/Offensive%20Course%20Path/pics/anatom_redirect.png?raw=true "AnatomyOfRedirection")<br>

### Terminal I/O Streams and Redirections

- Three I/O streams on terminal:

  - standard input (stdin),
  - standard output (stdout) and
  - standard error (stderr)

- Represented by **"file descriptors"** (think of them as ids):

  - `0` for stdin,
  - `1` for stdout,
  - `2` for stderr

- Angle bracket notation used for redirect to/from commands/files:

  - `>` send stream to a file
  - `<` receive stream from a file
  - `>>` to append
  - `<<` to in-place append (used in "heredoc")
  - `<<<` is used in "herestring" (not covering it in here)

- `&` is used to **"write into"** a stream, eg. `&1` to write into stdout

- Send stdout and stderr to same file:<br>
  `pip install rtv > stdouterr.txt 2>&1`<br>
  `ac -pd &> stdouterr.txt #short form (bash v4+)`

- Disregard both stdout and stderr:<br>
  `wget imgs.xkcd.com/comics/command_line_fu.png &> /dev/null #/dev/null is a "null" file to discard streams`

- Read from stdin as output of a command diff<br>
  `<(ls dirA) <(ls dirB)`

- Append stdout to a log file:<br>
  `sudo yum -y update >> yum_update.log`

### The pipe

A pipe is a Linux concept that automates redirecting the output of one command as input to a next command. Use of pipe leads to powerful combinations of independent commands. eg.:

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

- `wc < states.txt` **#OK**
- `wc states.txt` **#OK**
- There are some exceptions though
- Some receive input only from stdin and not from file, eg.

  - `tr 'N' 'n’ states.txt` #(strangely) **NOT OK**
  - `tr 'N' 'n’ < states.txt` **#OK**

- Some receive input neither from stdin nor from file, eg.

- `echo < states.txt` **#NOT OK** _(assuming want to print file contents)_

- `echo states.txt` **#NOT OK** _(assuming want to print file contents)_

- `echo "Hello miss, howdy? "` **#OK, takes literal args**

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

## Classic tools: find, grep, awk, sed

### find

search files based on a certain criteria

![Alt text](/Offensive%20Course%20Path/pics/find_criteria.png?raw=true "searchForAFile")<br>

#### Features of find

- path: may have multiple paths, eg. `find /usr /opt -iname "*.so"`
- criteria:

  - `-name, -iname`, `-type (f,d,l)`, `-inum <n>`
  - `-user <uname>`, `-group <gname>`, `-perm (ugo+/-rwx)`
  - `-size +x[c]`, `-empty`, `-newer <fname>`
  - `-atime +x`, `-amin +x`, `-mmin -x`, `-mtime -x`
  - criteria may be combined with logical **and** `(-a)` and **or** `(-o)`

- action:

  - `-print`: default action, display
  - `-ls`: run `ls -lids` command on each resulting file
  - `-exec cmd`: execute command
  - `-ok cmd`: like exec except that command executed after user confirmation

#### Examples of find

```
find . -type f -iname "*.txt" #txt files in curdir
find . -maxdepth 1 #equivalent to ls
find ./somedir -type f -size +512M -print #all files larger than 512M in ./somedir
find /usr/bin ! -type l #not symlinks in /usr/bin
find $HOME -type f -atime +365 -exec rm {} + #delete all files that were not accessed in a year
find . \( -name "*.c" -o -name "*.h" \) #all files that have either .c or .h extension
```

### grep

It searches for patterns in text. Extremely powerful and useful. **grep** originally was a command "global regular expression print" or 'g/re/p' in the ed text editor. It was so useful that a separate utility called **grep** was developed.

- grep will fetch lines from a text that has a match for a specific pattern
- Useful to find lines with a specific pattern in a large body of text, eg.:

  - look for a process in a list of processes
  - spot check a large number of files for occurrence of a pattern
  - exclude some text from a large body of text

### cut

The **cut** command is simple, but quite handy. It is used to extract a section of text from a line and output it to the standard output.

- Common switches:

  - `-f` for the field number we are cutting
  - `-d` for the field delimiter<br>
    `cut -d ":" -f 1 /etc/passwd`

#### Anatomy of grep

![Alt text](/Offensive%20Course%20Path/pics/grep_anatomy.png?raw=true "grepAnatomy")<br>

#### Useful grep options

- `-i`: ignore case
- `-n`: display line numbers along with lines
- `-v`: print inverse ie. lines that do not match the regular expression
- `-c`: print a count of lines of matches
- `-A<n>`: include n lines after the match
- `-B<n>`: include n lines before the match
- `-o`: print only the matched expression (not the whole line)
- `-E`: allows "extended" regular expressions that includes (more later)

#### Regular expressions

A regular expression (regex) is an expression that matches a pattern. Consider below example patterns:

```
^Linux is fun.$
^So is music.$
^Traffic not so much.$
```

- regex: _ba_ Results to: **nomatch**
- regex: _fun_ Results to: **one match="Linux is fun."**
- regex: _is_ Results to: **two matches="Linux is fun." and "So is music."**
- regex: _^so_ Results to: **one match="So is music."**
- regex: _ic.$_ Results to: **one match="So is music."**

- `.` is a Special character; will match any character (except newline) eg.<br>
  `b.t` will match bat, bbt, b%t, and so on but **not** bt, xbt etc.

- Character class: one of the items in the [] will match, sequences allowed:<br>
  `'[Cc]at'` will match Cat and cat<br>
  `'[f-h]ate'` will match fate, gate, hate

- `^` within a character class means negation eg.<br>
  `'b[^eo]at'` will match brat but not boat or beat

#### Extended regular expressions

This is enabled by using **egrep** or **grep -E**.

- `'*'` matches zero or more, `'+'` matches one or more, `'?'` matches zero or one occurrence of the previous character eg.<br>
  `[hc]+at` will match **hat, cat, hhat, chat, cchhat**, etc.
- `'|'` is a delimiter for multiple patterns, '(' and ')' let you group patterns eg.<br>
  `([cC]at)|([dD]og)` will match **cat, Cat, dog and Dog**
- `{}` may be used to specify a repetition range eg.<br>
  `ba{2,4}t` will match **baat, baaat and baaaat** but not **bat**

#### grep examples

- Lines that end with two vowels: `grep '[aeiou][aeiou]$' prose.txt`
- Check 5 lines before and after the line where term 'little' occurs: `grep -A5 -B5 'little' prose.txt`
- Comment commands and search later from history `some -hard 'to' \remember --complex=command #success` `history | grep '#success'`
- Confirm you got an ambiguous spelling right `grep -E '^ambig(uou|ou|ouo)s$' /usr/share/dict/linux.words`
- find+grep is one very useful combination `find . -iname "*.py" -exec grep 'add[_-]item' {} +`

#### awk: Extract and manipulate Data

A programmable filter that reads and processes input line by line. It has rich built-in features:

- explicit fields ($1 ... $NF) & records management
- functions (math, string manipulation, etc.)
- regular expressions parsing and filtering and also features like variables, loops, conditionals, associative arrays, user- defined functions

#### Anatomy of awk program

![Alt text](/Offensive%20Course%20Path/pics/awk_anatomy.png?raw=true "awkAnatomy")<br>
where **awk program** is:

```
BEGIN {actions} #run one time before input data is read

/pattern/ or condition {actions} #run actions for each line of
input files and/or stdin that satisfy /pattern or condition/

END {actions} #run one time after input processing section
```

At least one of the **BEGIN, /pattern/ or condition, {}, END** section needed

#### /patterns/, conditions and actions

- A pattern is a regex that matches (or not) to an input line, eg.

  ```
  /New/ # any line that contains
  ‘New’ /^[0-9]+ / # beginning with numbers
  /(POST|PUT|DELETE)/ # has specific words
  ```

- A condition is a boolean expression that selects input lines, eg.<br>
  `$3>1 # lines for which third field is greater than 1`

- An action is a sequence of ops, eg.

  ```
  {print $1, $NF} #print first and last field/col
  {print log($2)} #get log of second field/col
  {for (i=1;i<x;i++){sum += $3}} #get cumulative sum
  ```

- User defined functions may be defined in any action block

#### Useful awk one-liners

```
  awk '{print $1}' states.txt
  awk '/New/{print $1}' states.txt
  awk NF > 0 prose.txt # print lines that has at least one field (skip blank lines)
  awk '{print NF, $0}' states.txt #fields in each line and the line
  awk '{print length($0)}' states.txt #chars in each line
  awk 'BEGIN{print substr("New York",5)}' #York
```

### sed

**sed** parses and transforms text. It has the most complex structure and most powerful tool in someone's arsenal. However, because of complexity if you don't use it very often you will forget the syntax. sed is a stream editor. Looks for a pattern in text and applies changes (edits) to them.

- A batch or non-interactive editor
- Reads from file or stdin (so, pipes are good) **one line at a time**
- The original input file is unchanged (sed is also a filter), results are sent to standard output
- It is most frequently used for **text substitution**.

#### Anatomy of awk program

![Alt text](/Offensive%20Course%20Path/pics/sed_anatomy.png?raw=true "sedAnatomy")<br>

#### sed Options

- address: may be a line number, range, or a match; default: whole file
- command:

  - `s`:substitute,
  - `p`:print,
  - `d`:delete,
  - `a`:append,
  - `i`:insert,
  - `q`:quit

- regex: A regular expression

- delimiter: Does not have to be `/`, can be `|` or `:` or any other character

- modifier: may be a number `n` which means apply the command to nth occurrence, `g` means apply globally in the line

- Common sed flags:

  - `-n` (no print),
  - `-e` (multiple ops),
  - `-f` (read sed from file),
  - `-i` (in place edit **[careful here]**)

#### Usefull examples of sed

```
  sed -n '5,9p' states.txt #print lines 5 through 9
  sed '20,30s|New|Old|1' states.txt #affects 1st occurrence in ln20-30
  sed -n '$p' states.txt #print last line
  sed '1,3d' states.txt #delete first 3 lines
  sed '/^$/d' states.txt #delete all blank lines
  sed '/York/!s/New/Old/' states.txt #substitute except York
  kubectl -n kube-system get configmap/kube-dns -o yaml | sed 's/8.8.8.8/1.1.1.1/' | kubectl replace -f -
```

## SSH Config and Tunneling

### ssh config (~/.ssh/config)

```
Host login1
  hostname login1.ornl.gov
  User km0

Host cades
  Port 22
  hostname or-slurm-login.ornl.gov
  ProxyJump login1
  User km0
  ServerAliveCountMax=3 #max num of alive messages sent without ack ServerAliveInterval=15 #send a null message every 15 sec
```

> now to ssh/scp to cades, just need "ssh/scp cades ..."

### Benefits of ssh config

Makes ssh commands easier to remember in case of multiple hosts

- Customises connection to individual hosts
- And much more, see man 5 ssh_config
- For example: **ssh summit** is sufficient to connect to **summit.olcf.ornl.gov** with all the properties mentioned in the section:

  ```
  Host summit
   Port 22
   hostname summit.olcf.ornl.gov
   User ketan2
   ServerAliveCountMax=3
   ServerAliveInterval=15
  ```

### Port forward over SSH Tunnel

![Alt text](/Offensive%20Course%20Path/pics/ssh_portForward.png?raw=true "sshPortForward")<br>

#### SSH Tunneling Example

Run an HTTP server on remote node and browse through local web browser:

1. `remote$ python2 -m SimpleHTTPServer 25000` OR `remote$ python3 -m http.server 25000`
2. `local$ ssh -L 8000:localhost:25000 id@remote -N`
3. Open browser on local and navigate to <http://localhost:8000>

#### Incremental Remote Copy with rsync

Synchronise data between local and remote storage

- Rich set of options (see man) `-a` and `-v` most commonly used<br>
  `rsync -av localdir/ remotehost:~/remotedir`<br>
  trailing `/` imp in localdir, else, the dir will be synced not contents
- A useful rsync hack: **fast deletion of a large directory**<br>
  `mkdir empty && rsync -a --delete empty/ large_dir/`

## Secure Communication with GnuPG

### GNU Privacy Guard Basics

A tool for secure communication. We cover:

- keypair creation
- key exchange and verification
- encrypting and decrypting documents
- authenticating documents with digital signatures

### Create a new keypair

- Creation: `gpg --gen-key #answer the prompted questions`

  - Provide name and email as ID, choose hard-to-guess passphrase
  - Keypair artefacts in `$HOME/.gnupg` dir

- Create a revocation certificate<br>
  `gpg --output revoke.asc --gen-revoke <ID>`

  - use the email as ID
  - Useful to notify others the keypair may no longer be used -- eg. if you forgot your passphrase, lost keypair etc.

### Key Exchange and Verification

- Export a public key<br>
  `gpg --output pub.gpg --export <ID> #binary gpg --armor --export <ID> > pubtxt.gpg #ascii`
- Import a public key<br>
  `gpg --import billpub.gpg #import Bill's pubkey`
- Verify and sign an imported key<br>
  `gpg --edit-key b@ms.us #out key info & prompt`<br>
  `command> fpr #fingerprint, verify over phone`<br>
  `command> sign #verify at prompt and done!`

### Encrypting and Decrypting Documents

- Encrypt a document for Bill using Bill's public key<br>
  `gpg --output doc_pdf.gpg --encrypt --recipient b@ms.us doc.pdf #must have Bill's public key`
- Bill Decrypts the document (must have his private key & passphrase)<br>
  `gpg --output doc.pdf --decrypt doc_pdf.gpg`
- Documents may be encrypted without key, just with passphrase<br>
  `gpg --output doc_pdf.gpg --symmetric doc.pdf Enter passphrase:`

### Authenticate Docs with Digital Signatures

- Digitally signed document ensure they are authentic & untempered<br>
  `gpg --output doc.signed --sign doc.pdf`<br>
  `Enter Passphrase:`<br>
  Must have the private key to sign

- A signed document can be verified and decrypted like so:<br>
  `gpg --ouput doc.pdf --decrypt doc.signed` Must have owner's public key

## Managing Services

### Generic Services

To see a table of all available services within linux enviornment, run **systemctl** with the **list-unitfiles** option:<br>
`systemctl list-unit-files`

#### SSH Service

The Secure SHell service is most commonly used to remotely access a computer, using a secure, encrypted protocol.

- It is a TCP-based and listens by default on port 22.
- To start the SSH service, we run **systemctl** with the **start** option followed by the service name<br>
  `sudo systemctl start ssh`<br>

- Verify via: `sudo ss -antlp | grep sshd`

- Enabling the service by default: `sudo systemctl enable ssh`<br>
  **Services can be enabled or disabled by default via `systemctl`**<br>

  #### HTTP Service

  The Apache HTTP service is often used for hosting a site, or providing a platform for downloading files to a machine.

- The HTTP service is TCP-based

- listens by default on port 80

- To start the service we run **systemctl** with the **apache2** option: `sudo systemctl start apache2`<br>

- Verify via: `sudo ss -antlp | grep apache`

- Enabling the service by default: `sudo systemctl enable apache2`<br>

## Bash tools

### Bash Shell Basics

Commands and utilities such as **grep, sed, awk** may be invoked

- Variables, constants, conditionals, loops and functions may be defined - Arithmetic operations available
- Logical operations && (AND) and || (OR) available:

  - `wget ...|| curl ...`: run _curl_ iff _wget_ fails
  - `make install && make test` : test iff install succeeds

- Shell "Startup" files set environment as you start your shell

  - `.bashrc` : a file that runs in each new shell that is spawned
  - `.bash_profile` : a file that runs only in a "login shell" (and not all shells eg. it won't run if you invoke a shell script that creates a subshell)

### Aliases and Functions

Aliases are short and convenient names for long commands

- They are usually defined in `.bashrc` or a separate `.aliases` file
- To temporarily bypass an alias (say we aliased `ls` to `ls -a`), use `\: \ls`
- Bash functions are usually defined in `.bashrc/.bash_profile`
- Functions are more expressive and preferred over aliases

#### Examples of useful aliases

```
  alias s=ssh
  alias c=clear
  alias cx='chmod +x'
  alias ls='ls -thor'
  alias more=less
  alias ps='ps auxf'
  alias psg='ps aux | grep -v grep | grep -i -e USER -e' alias ..='cd ..'
  alias myp='ps -fjH -u $USER'
  alias cleanup='rm -f *.tmp *.aux *.log'
```

#### Examples of useful Functions

```
mcd() { mkdir -p $1; cd $1 }
cdl() { cd $1; ls}
backup() { cp "$1"{,.bak};} #test first
gfind() { find / -iname $@ 2>/dev/null }
lfind() { find . -iname $@ 2>/dev/null }
rtfm() { help $@ || man $@ || $BROWSER "http://www.google.com/search?q=$@"; }
```

- See `/usr/share/doc/bash-*/examples/functions` for more function examples

### Variables and Command Substitution

- Variables are implicitly typed
- May be a literal value or command substitute `vname=value #assign value to variable vname` `$vname #read value of variable vname`

  ```
  #!/bin/sh
  msg="Hello World"
  echo $msg
  ```

- Command substitution:

  ```
  curdir=$(pwd)
  curdate=$(date +%F)
  echo "There are $(ls -1 | wc -l) items in the current dir"
  ```

### Conditionals

if-then-else construct to branch similar to programming languages

- Two forms of conditional evaluation mechanisms:

  - `test` and `[ ... ]`

    ```
    $ if test $USER = 'km0'; then echo 'I know you';
    else echo 'Who are you'; fi
    ```

    vs.

    ```
    $ if [ -f /etc/yum.conf ]; then echo 'yum.conf
    exists'; else echo 'file do not exist'; fi
    ```

#### Conditionals summary

- string

  - `-z string`: length of string 0
  - `-n string`: length of string not 0
  - `string1 = string2`: strings are identical (note a single =)

- numeric

  - `int1 -eq int2`: first int equal to second
  - `-ne`, `-gt`, `-ge`, `-lt`, `-le`: not-equal, greater-than, -greater-or-equal...

- file

  - `-r filename`: file exists and is readable
  - `-w filename`: file exists and is writable
  - `-f`, `-d`, `-s`: regular file, directory, exists and not empty

- logic

  - `!`, `-a`, `-o`: negate, logical and, logical or

#### loops

- Basic structure (three forms):<br>
  `for i in {0..9}; do echo $i; done`<br>
  `for ((i=0;i<10;i++)){ echo $i;} #C-like`<br>
  `for var in list; do command; done #'python-like'`
- often used with command substitution:<br>
  `for i in $(\ls -1 *.txt); do echo "$i"; done`<br>
  `for i in $(get_files.sh); do upload.sh "$i"; done`

## Program Development Tools

### Programming Language Platforms

- Interpreted programming platforms available on most systems

  - Python, Perl, awk, bash
  - We covered awk, some bash and a bit of python

- Compiled programming platforms available on most systems

  - C, Fortran
  - We cover C in this section

- Additionally, a build system called **Make** is available

### Elements of C Program Development

- The source code that is written/edited by a programmer

  - Often split into header files (.h) and source code files (.c)

- The compiler gcc does the following:

  - compile (-S ) convert the source code (.c) to assembly code (.s)
  - assemble (-c ) - translate the assembly code to object code (.o)
  - link (-l ) - link to the standard libraries to produce executable

- By default gcc combines the above stages producing the executable<br>
  `gcc hello.c #creates a.out; no .o or .s files`

### The "make" build system

- Automates compilation of multiple source files in a complex project
- Streamlines dependent actions and performs them in order
- Reads configuration from a "build" file usually named as Makefile
- Makefile acts as an artefact of project build process

### Anatomy of Make files

![Alt text](/Offensive%20Course%20Path/pics/makeFile_anatomy.png?raw=true "makeFileAnatomy")<br>

### How the make command works

The make command will read from the Makefile and run commands in order to build the ultimate target.<br>
For instance, in the Makefile shown in above section, `make` will run commands for rule 2-4 followed by rule 1:

```
  gcc -c dep1.c #create dep1.o
  gcc -c dep2.c #create dep2.o
  gcc -c main.c #create main.o
  gcc -o an_exe main.o dep1.o dep2.o -lm
```

## Miscellaneous Utilities

### Get things done at specific times with "at"

- **at** will execute the desired command on a specific day and time

  ```
  at 17:00 #press enter
  at> log_days_activities.sh #smtimes no at> prompt
  [ctrl-d]
  ```

- **at** offers keywords such as _now, noon, today, tomorrow_

- offers terms such as _hours, days_ to be used with the + symbol

  ```
  at noon
  at now + 1 year
  at 3:08pm + 1 day
  at 15:01 December 19, 2018
  ```

### Get things done periodically with cron

- cron will execute the desired command periodically
- A crontab file controls and specifies what to execute when
- An entry may be created in any file and added to system with the crontab command like so:<br>
  `echo '15 18 30 6 * find /home -mtime +30 -print' > f00 crontab f00 #add above to system crontab`<br>
  `crontab -l #list crontab entries`<br>
  `crontab -r #remove crontab entries`
- Output of the cron'd command will be in mail (alternatively it may be redirected to a file with '>')
- What does the entries in a crontab mean though? (see next)

### Anatomy of Cron

![Alt text](/Offensive%20Course%20Path/pics/cron_anatomy.png?raw=true "cronAnatomy")<br>
**Run the find command on June 30 of every year at 6:15 PM no matter what day of week it is.**

### math

- Generate random number using shuf (may need to install) `shuf -i 1-100 -n 1`
- Format numbers with numfmt<br>
  `numfmt --to=si 1000 1.0K`<br>
  `numfmt --from=iec 1K 1024`
- bc is a versatile calculator<br>
  `bc <<< 48+36 #no space on either side of +`<br>
  `echo 'obase=16; ibase=10; 56'|bc #decimal to hex`<br>
  `echo 'scale=8; 60/7.02' |bc #arbitrary precision`

### Python utilities

- Stand up a simple web server in under a minute with Python<br>
  `python3 -m http.server 35000`
- Pretty print a json file<br>
  `python3 -m json.tool afile.json`
- Run small python programs<br>
  `python -c "import math; print(str(math.pi)[:7])"`
- Do arithmetic `python -c "print(6*6+20)"`<br>
  `python -c "fctrl=lambda x:0_*x or x_fctrl(x-1); print(fctrl(6))" #compute factorial`

## Random Stuff

- Run a command for specified time using timeout:<br>
  `timeout 2 ping google.com`
- watch a changing variable<br>
  `watch -n 5 free -m`
- Say yes and save time<br>
  `yes | pip install pkg --upgrade`<br>
  `yes "this is a test" | head -50 > testfile.txt # create file with arbitrary no. of lines`
- Create pdf from text using vim :<br>
  `vim states.txt -c "hardcopy > states.ps | q" && ps2pdf states.ps #convert ps to pdf`
- Run a command as a different Linux group<br>
  `sg grpgit -c 'git push'`

- Display a csv in columnar/tabular format<br>
  `column -t -s , filename.csv`

- Have difficulty sending binary executables over emails?<br>
  `xxd f.exe f.hex #hexdump the exe, send over email`<br>
  `xxd -r f.hex f.exe #receiver convert back to exe`

- Generate password<br>
  `head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8`<br>
  `openssl rand 8 -base64 | cut -c1-8 #-base64 8 for some version`

- pandoc to convert between md, tex, txt, html, docx, pdf, odt

  ```
  pandoc manual.md -o manual.pdf
  pandoc example.txt -o example.html
  pandoc -s example.txt -o example.docx
  ```

- Parse and read **xml** files with `xmllint`

- Split a large file into small chunks (eg. to send as attachment in mail)<br>
  `split -b 20M large.tgz parts_ #20MB chunks #send parts_* over mail`<br>
  `cat parts_a* > large.tgz #at receiving end`

_Some of Material Belongs to "Ketan M. (km0@ornl.gov)"_<br>
_Some of material I gathered I can't remember for where; If you it was you, let me know and I buy you a beer_
