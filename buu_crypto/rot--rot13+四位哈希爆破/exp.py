import hashlib
a = [83,89,78,84,45,86,96,45,115,121,110,116,136,132,132,132,108,128,117,118,134,110,123,111,110,127,108,112,124,122,108,118,128,108,131,114,127,134,108,116,124,124,113,108,76,76,76,76,138,23,90,81,66,71,64,69,114,65,112,64,66,63,69,61,70,114,62,66,61,62,69,67,70,63,61,110,110,112,64,68,62,70,61,112,111,112]
b = []
for i in a:
    i = i-13
    b.append(i)

for j in b:
    print(chr(j),end='')


flag = 'flag{www_shiyanbar_com_is_very_good_'
flag_md5 = '38e4c352809e150186920aac37190cbc'
m='38e4c352809e150186920aac37190cbc'
t="flag{www_shiyanbar_com_is_very_good_"

def doit():
    count=0
    for i in range(33, 127):
        for j in range(33, 127):
            for k in range(33, 127):
                for c in range(33, 127):
                    s = t + chr(i) + chr(j) + chr(k) + chr(c) + '}'
                    x = hashlib.md5(s.encode()).hexdigest()
                    count=count+1
                    print(count)
                    if m == x:
                        print(s)
                        return
doit()
