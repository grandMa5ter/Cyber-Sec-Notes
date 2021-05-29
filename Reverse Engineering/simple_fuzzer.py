#!/usr/env python2
#Simple fuzzer

import subprocess

param = "bufferOverflow "

for i in range(0xa1, 0xff):
    param += chr(i)

subprocess.call(param)
