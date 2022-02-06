# Dictionary
hashcat -m 0 -a 0 hashfile dictionary.txt -O --user -o result.txt

# Dictionary + rules
hashcat -m 0 -w 3 -a 0 hashfile dictionary.txt -O -r haku34K.rule --user -o result.txt

# Mask bruteforce (length 1-8 A-Z a-z 0-9)
hashcat -m 0 -w 3 -a 3 hashfile ?1?1?1?1?1?1?1?1 --increment -1 --user ?l?d?u
hashcat -m 0 -w 3 -a 3 hashfile suffix?1?1?1 -i -1 --user ?l?d

# Modes
-a 0 = Dictionary (also with rules)
-a 3 = Bruteforce with mask 

# Max performance options
--force -O -w 3 --opencl-device-types 1,2

# Output results
-o result.txt

# Ignore usernames in hashfile
--user/--username

# Masks
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff

# Mask Processor generator line 12 Chars
.\mp64.exe ?a?a?a?a?a?a?a?a?a?a?a?a -o ..\hash_files\kev_created_12Char_wordlist.txt

**for basic attacks refer to hashcat --help ot wiki**

  - Wordlist + Rules hashcat -a 0 -m hashtype hashfile wordlist -r best64.rule
  - Brute-Force hashcat -a 3 -m hashtype hashfile ?a?a?a?a?a?a
  - Combinator hashcat -a 1 -m 0 hashtype wordlist1 wordlsit2

.\hashcat.exe -m 18200 -w 3 -a 0 ..\hash_files\cms_domain_user_hash.txt ..\hash_files\kev_created_12Char_wordlist.txt ..\hash_files\realhuman_phill.txt -O -r ..\hash_file\OneRuleToRuleThemAll.rule --user -o result.txt

.\hashcat.exe -m 18200 -w 3 -a 0 ..\hash_files\cms_domain_user_hash.txt ..\hash_files\realhuman_phill.txt -O -r ..\hash_files\OneRuleToRuleThemAll.rule --user -o result.txt
## ASRep Hash
.\hashcat.exe -m 18200 -w 3 -a 0 ..\hash_files\domain_user_hash.txt ..\hash_files\kev_created_12Char_wordlist.txt ..\hash_files\realhuman_phill.txt -O -r ..\hash_file\OneRuleToRuleThemAll.rule --user -o result.txt

.\hashcat.exe -m 18200 -w 3 -a 0 ..\hash_files\domain_user_hash.txt ..\hash_files\realhuman_phill.txt -O -r ..\hash_files\OneRuleToRuleThemAll.rule --user -o result.txt
