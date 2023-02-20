


code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']

for i in range(len(code)):
    code[i] = ord(code[i])
print(code)
for i in range(len(code)-2,-1,-1):
    code[i] = code[i] ^ code[(i + 1)]
print(code)
for i in range(len(code)):
    if code[i]-i>0x20 and code[i]-i<0x7e:
        print(chr(code[i]-i),end='')
    else:
        print(chr(code[i]+128-i), end='')
