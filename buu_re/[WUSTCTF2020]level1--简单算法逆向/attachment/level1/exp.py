key = '''198
232
816
200
1536
300
6144
984
51200
570
92160
1200
565248
756
1474560
800
6291456
1782
65536000
'''
key = key.split()
print(len(key))
flag = ''
for i in range(1,20):
    temp = int(key[i-1])
    if i & 1 != 0:
        flag += chr(temp>>i)
    else:
        flag += chr(temp//i)
print(flag)
