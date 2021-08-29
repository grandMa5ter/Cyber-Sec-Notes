#!/usr/bin/env python3

import socket

print("Script to fuzz vulnserver")
va = "192.168.56.101"
vp = 9999
cmd = b"HTER "

sock = socket.socket()
conn = sock.connect((va, vp))

for i in range(4, 100000, 4):
	message = cmd + b"A" * i
	print("Sending command", cmd, "with arg length", i)
	sock.sendall(message)
	resp =sock.recv(4096)
	print(b"Received response:", resp)



