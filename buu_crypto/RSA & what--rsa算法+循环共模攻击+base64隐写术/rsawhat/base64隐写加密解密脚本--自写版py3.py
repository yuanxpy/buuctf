# -*- coding: cp936 -*-
import base64

def replace_char(string,index,char):
    string = list(string)
    string[index] = char
    return ''.join(string)

def enhide_base64(filename,hide_content):
    bin_str = ''
    base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    for c in hide_content:
        bin_str += bin(ord(c)).replace('0b','').zfill(8)
    #获取需要隐写字符串的二进制字符串
    with open(filename,'rb') as f0 ,open(filename+'隐写后.txt','w') as f1:
        for line in f0.readlines():
            normal_str = base64.b64encode(line.replace(b'\n',b'')).decode('utf-8')
            equal_num = normal_str.count('=')
            #判断该行是否可以进行隐写
            if equal_num and len(bin_str):
                offset = int('0b'+bin_str[:equal_num*2],2)  #base64隐写原则，两个等于号可以隐写4位，一个可以隐写2位
                char = normal_str[len(normal_str)-equal_num -1]  #获取需要改变的隐写字符
                new_char = base64_table[base64_table.index(char)+offset]
                hide_str = replace_char(normal_str,len(normal_str)-equal_num -1,new_char)
                bin_str = bin_str[equal_num*2:]
            else:
                hide_str = normal_str
            f1.write(hide_str+'\n')

def dehide_base64(filename):
    bin_str = ''
    base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    with open(filename,'r') as f:
        for line in f.readlines():
            #hide_str = line.decode('utf-8').replace('\n','')
            #原本采用rb的文件读取方式+上面这行代码读入hide_str,但不知道为什么去不掉结尾的回车导致下面无法进行，最终选择使用r+下面这行代码读入hide_str
            hide_str = ''.join(line.split())
            normal_str = base64.b64encode(base64.b64decode(hide_str)).decode('utf-8')
            #获取正常base64字符和hide版本的base64编码
            offset = abs(base64_table.index(hide_str.replace('=','')[-1])-base64_table.index(normal_str.replace('=','')[-1]))
            equal_num = normal_str.count('=')
            #获取偏移和可隐写位数
            if equal_num:
                bin_str += bin(offset)[2:].zfill(equal_num*2)
        for i in range(0,len(bin_str),8):
            print(chr(int(bin_str[i:i+8],2)),end='')
    f.close()
    print('')

dehide_base64('result.txt')