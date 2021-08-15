# Web App-Directory Busting
**This is thanks to @S1REN generic guidance and also notes. So, not mine and I copied it.**

**[Nikto]**<br>
`nikto --host $URL -C all`

**[GOBUSTER]**

- **We will begin with Gobuster.**<br>
  `export URL="https://example.com/"`

- **Here are my localized commands:**<br>
  **BUST DIRECTORIES:**<br>
  `gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -l -k -t 30`

**BUST** **FILES:**<br>
`gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -l -k -t 30`

**BUST SUB-DOMAINS:**<br>
`gobuster dns -d someDomain.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30`

**-->** _Make sure any DNS name you find resolves to an in-scope address before you test it_.

**BUST DIRECTORIES with DIRSEACH:**<br>
`sudo python3 /opt/dirsearch/dirsearch.py -u <http://$IP/> -e php,html,jsp,aspx,js -x 400,401,403` Or you can do this: `sudo python3 /opt/dirsearch/dirsearch.py -u http://$IP:$Port -e php,html,jsp,aspx,js -x 400,401,403 -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt`

**===========================================================================**

**[WFUZZ]**<br>
`export URL="https://example.com/**FUZZ**"`

**FUZZ DIRECTORIES:**<br>
`export URL="https://example.com/$FUZZ/" wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt "$URL" |grep -ivE '404'`

**FUZZ FILES:**<br>
`wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt "$URL" |grep -ivE '404'`

**AUTHENTICATED FUZZING:**<br>
e.g.

```
wfuzz -c -b "<SESSIONVARIABLE>=<SESSIONVALUE>" -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt "$URL" |grep -ivE '404'
```

**FUZZ DATA AND CHECK FOR PARAMETERS:**<br>
export URL="<https://example.com/?parameter=**FUZZ**><br>
**-->** and/or some combination of...

```
export URL="https://example.com/?**FUZZ**=data
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"
```

- **Can I FUZZ Post Data?**<br>
  **-->** Yup.<br>
  **-->** Example of Command Injection **POST Checks**:<br>
  `wfuzz -c -z file,/usr/share/wordlists/Fuzzing/command-injection.txt -d "postParameter=$FUZZ" "$URL"`
