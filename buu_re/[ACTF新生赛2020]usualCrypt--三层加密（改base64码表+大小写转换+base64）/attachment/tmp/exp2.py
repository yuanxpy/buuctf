key = 'zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9'.swapcase()
table1 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
offset = 10
for i in range(6,15):        #进行base64表的转换
    # temp = table1[i+10]
    # table1[i+10] = table1[i]
    # table1[i] = temp
    table1[i],table1[i+offset] = table1[i+offset],table1[i] #python的交换更简洁
print(table1)

str_table = ''
for i in table1:
    str_table+=i
print(str_table)

import base64
a = str_table
b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
base_fix = key
table = ''.maketrans(a, b)
print(base64.b64decode(base_fix.translate(table)))
