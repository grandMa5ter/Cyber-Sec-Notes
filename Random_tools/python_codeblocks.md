
## Read the archive and print the list of files inside it

```
import zipfile
f=zipfile.ZipFile("secret.zip")
f.printdir()
f.close
```
## Generate a dictionary "dict.txt" containing all possible passwords, matching the password policy

```
import itertools
alphabets = ['a', 'b', 'c', 'd', 'e', '1', '2', '3', '4', '5']
perm = [''.join(p) for p in itertools.permutations(alphabets)]
f = open("dict.txt", "w")
for passleng in [6]:
    combinations = itertools.product(alphabets, repeat=passleng)
    for combination in combinations:
        f.write(''.join(combination)+'\n')

```

## Bruteforce the "secret.zip" using the generated dictionary file and print the correct password

```
import zipfile
cracked = False
z = zipfile.ZipFile("secret.zip")
with open("dict.txt") as f:
    lines = f.readlines()
for password in lines:
    password = password.replace('\n','')
    try:
        z.extractall(pwd=password)
        correct_password = 'Correct password: %s' % password
        cracked = True
        break
    except:
        pass

if cracked:
    print correct_password
else:
    print "Password not found"
```

## Print the contents of all the extracted file

```
import zipfile
z = zipfile.ZipFile("secret.zip")
files = z.namelist()
z.setpassword("b1c1e5")
z.extractall()
z.close()
for extracted_file in files:
    print "File name:"+extracted_file+"\n\nContent:"
    with open(extracted_file) as f:
        content = f.readlines()
        print ''.join(content)
        print '\n\n'
```

## Bruteforce the "secret.pdf" using the generated dictionary file and print the correct password

```
from PyPDF2 import PdfFileReader, PdfFileWriter

cracked = False

# Loading passwords
with open("dict.txt") as f:
    lines = f.readlines()

# Opening file
with open('secret.pdf', 'rb') as input_file:
    reader = PdfFileReader(input_file)
    for password in lines:
        password = password.replace('\n','')
        try:
            status = reader.decrypt(password)
            if status == 1:
                correct_password = 'Correct password: %s' % password
                cracked = True
                break
        except:
            pass

if cracked:
    print correct_password
else:
    print "Not cracked"
```


## Print the content of "secret.pdf" using the correct password

```
from PyPDF2 import PdfFileReader, PdfFileWriter

encrypted_file='secret.pdf'
password='bac321'
with open(encrypted_file, 'rb') as input_file:
    reader = PdfFileReader(input_file)
    reader.decrypt(password)
    for i in range(reader.getNumPages()):
            page = reader.getPage(i)
            page_content = page.extractText()
            print page_content.encode('utf-8')
```


## Decrypt the "secret.pdf" using the correct password and save the decrypted file

```
from PyPDF2 import PdfFileReader, PdfFileWriter

encrypted_file='secret.pdf'
decrypted_file='decrypted.pdf'
password='bac321'
with open(encrypted_file, 'rb') as input_file, open(decrypted_file, 'wb') as output_file:
    reader = PdfFileReader(input_file)
    reader.decrypt(password)

    writer = PdfFileWriter()

    for i in range(reader.getNumPages()):
        writer.addPage(reader.getPage(i))

    writer.write(output_file)
```

## Print the metadata from the decrypted file
```
from PyPDF2 import PdfFileReader, PdfFileWriter

# Opening file
with open('decrypted.pdf', 'rb') as input_file:
    reader = PdfFileReader(input_file)
    print reader.getDocumentInfo()
```
