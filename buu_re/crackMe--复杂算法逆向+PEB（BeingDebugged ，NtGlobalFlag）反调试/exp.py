import hashlib

box = [0x2a, 0xd7, 0x92, 0xe9, 0x53, 0xe2, 0xc4, 0xcd]
s = "dbappsec"

secret = []

for i in range(len(s)):
    secret.append(hex(ord(s[i])^box[i]).replace("0x",''))
print(secret)
flag = ''.join(secret)
print(flag)
md = hashlib.md5()
md.update(flag.encode('utf-8'))
print ("flag{"+md.hexdigest()+"}")