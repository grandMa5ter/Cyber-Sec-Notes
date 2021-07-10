##!/usr/bin/env python3
# fuzzer2.py

import socket

IP = "<IP>"
PORT = <PORT>

payload = 1000 * "A"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP,PORT))
    s.send(payload)
    print "[+] " + str(len(payload)) + " Bytes Sent"
except:
    print "[-] Crashed"
