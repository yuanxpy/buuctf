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
    #��ȡ��Ҫ��д�ַ����Ķ������ַ���
    with open(filename,'rb') as f0 ,open(filename+'��д��.txt','w') as f1:
        for line in f0.readlines():
            normal_str = base64.b64encode(line.replace(b'\n',b'')).decode('utf-8')
            equal_num = normal_str.count('=')
            #�жϸ����Ƿ���Խ�����д
            if equal_num and len(bin_str):
                offset = int('0b'+bin_str[:equal_num*2],2)  #base64��дԭ���������ںſ�����д4λ��һ��������д2λ
                char = normal_str[len(normal_str)-equal_num -1]  #��ȡ��Ҫ�ı����д�ַ�
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
            #ԭ������rb���ļ���ȡ��ʽ+�������д������hide_str,����֪��Ϊʲôȥ������β�Ļس����������޷����У�����ѡ��ʹ��r+�������д������hide_str
            hide_str = ''.join(line.split())
            normal_str = base64.b64encode(base64.b64decode(hide_str)).decode('utf-8')
            #��ȡ����base64�ַ���hide�汾��base64����
            offset = abs(base64_table.index(hide_str.replace('=','')[-1])-base64_table.index(normal_str.replace('=','')[-1]))
            equal_num = normal_str.count('=')
            #��ȡƫ�ƺͿ���дλ��
            if equal_num:
                bin_str += bin(offset)[2:].zfill(equal_num*2)
        for i in range(0,len(bin_str),8):
            print(chr(int(bin_str[i:i+8],2)),end='')
    f.close()
    print('')

dehide_base64('result.txt')