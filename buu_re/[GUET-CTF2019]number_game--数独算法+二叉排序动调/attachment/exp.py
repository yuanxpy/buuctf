# -*- coding:utf-8 -*-

model = [7, 3, 8, 1, 9, 4, 0, 5, 2, 6]
s = [48, 52, 50, 49, 52, 50, 49, 52, 51, 48]

flag = [0] * 10

for i in range(10):
    flag[model[i]] = s[i]
print ('flag{' + ''.join([chr(x) for x in flag]) + '}')