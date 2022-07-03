# Web App-Directory Busting

**This is thanks to @S1REN generic guidance and also notes. So, not mine and I copied it.**

## Nikto
`nikto --host $URL -C all`

## GOBUSTER

- We will begin with Gobuster
  `export URL="https://example.com/"`
- Here are my localized commands:
  - BUST DIRECTORIES: `gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -l -k -t 30`
  - BUST FILES: `gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -l -k -t 30`
  - BUST SUB-DOMAINS: `gobuster dns -d someDomain.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30`
*Make sure any DNS name you find resolves to an in-scope address before you test it.*

## DIRSEACH:
- `sudo python3 /opt/dirsearch/dirsearch.py -u <http://$IP/> -e php,html,jsp,aspx,js -x 400,401,403` 
- Or you can do this: `sudo python3 /opt/dirsearch/dirsearch.py -u http://$IP:$Port -e php,html,jsp,aspx,js -x 400,401,403 -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt`

## WFUZZ

- Simple: `export URL="https://example.com/**FUZZ**"`
- FUZZ DIRECTORIES: `export URL="https://example.com/$FUZZ/" wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt "$URL" |grep -ivE '404'`
- FUZZ FILES: `wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt "$URL" |grep -ivE '404'`

- AUTHENTICATED FUZZING: `wfuzz -c -b "<SESSIONVARIABLE>=<SESSIONVALUE>" -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt "$URL" |grep -ivE '404'`
- FUZZ DATA AND CHECK FOR PARAMETERS:
  - `export URL="<https://example.com/?parameter=**FUZZ**>`
  - Try the combination of all these

  - `export URL="https://example.com/?**FUZZ**=data`
  - `wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"`

- FUZZ Post Data
  - Example of Command Injection **POST Checks**: `wfuzz -c -z file,/usr/share/wordlists/Fuzzing/command-injection.txt -d "postParameter=$FUZZ" "$URL"`
