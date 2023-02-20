s = '28 30 23 08 17 10 16 30'
s = s.split(' ')
for i in s:
    temp = int(i) + 60
    print(chr(temp),end='')


