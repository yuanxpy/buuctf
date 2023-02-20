import base64
string = 'e3nifIH9b_C@n@dH'
flag =''
flag1 = ''
for i in range(len(string)):
    flag += chr(ord(string[i])-i)
flag1 = base64.b64decode(flag)
print(flag1)