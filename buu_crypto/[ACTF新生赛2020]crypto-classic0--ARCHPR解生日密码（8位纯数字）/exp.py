f = open('cipher','rb')
content = f.read()
for i in content:
    result = (i ^ 0x7) + 3
    print(chr(result),end='')