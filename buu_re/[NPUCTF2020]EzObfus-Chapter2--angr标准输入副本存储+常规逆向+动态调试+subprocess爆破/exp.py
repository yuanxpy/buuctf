memory=[
  0x6E, 0x10, 0xEC, 0x13, 0xC1, 0xCB, 0xF0, 0x2D, 0xC6, 0x32,
  0xFD, 0x86, 0xEE, 0xCB, 0x89, 0x92, 0x3C, 0x46, 0x49, 0x71,
  0x62, 0x57]

memory2 = [
  0x21, 0x3F, 0xA3, 0xe9, 0x8f, 0]

flag = 'n'
for i in range(1,len(memory),1):
  temp = ((memory[i] << 3) & 0xff) | (memory[i] >> 5)
  # print(temp)
  sub_value = ((memory2[i%6]>>6) ^ ((memory2[(i-1)%6]<<4)&0xff))
  # print(sub_value)
  temp = temp - sub_value
  temp &= 0xff
  flag += chr(temp)

print(flag)


a = flag    #刚才得到的字符串前面加“n”
for i in range(len(a)):
    flag = ''
    flag += chr((ord(a[i])^i)-i)  #通过动调得到
    print(flag,end='')
print()

from itertools import *
import subprocess   #subprocess 模块允许你生成新的进程，连接它们的输入、输出、错误管道，并且获取它们的返回码
for i in range(1):
    for j in range(32,127):
        for k in range(32,127):
            flag ="npuctf{WDNMD_"+chr(j)+chr(k)+"_OBFU!}"
            p = subprocess.Popen([r"./attachment.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.stdin.write(bytes(flag,encoding='utf-8'))
            p.stdin.close()
            out=p.stdout.read()
            p.stdout.close()
            if "E".encode() not in out:
                print(flag)
                exit()