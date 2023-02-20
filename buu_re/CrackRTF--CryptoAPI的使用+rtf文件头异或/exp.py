

import hashlib

flag = "@DBApp"

for i in range(100000,999999):
	s = str(i) + flag
	x = hashlib.sha1(s.encode())
	cnt = x.hexdigest()
	if "6e32d0943418c2c" in cnt:
		print(cnt)
		print(str(i)+flag)
#sha1加密爆破第一轮密码

s = "{\\rtf1"

a = [0x05,0x7D,0x41,0x15,0x26,0x01]

flag1 = ""
for i in range(0,len(s)):
	x = ord(s[i]) ^ a[i]
	flag1 += chr(x)
print(flag1)
#rtf文件头异或得到第二轮密码