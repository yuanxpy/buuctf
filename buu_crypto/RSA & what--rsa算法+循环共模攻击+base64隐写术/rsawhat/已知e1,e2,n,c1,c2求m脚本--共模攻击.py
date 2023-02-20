import gmpy2
from Crypto.Util.number import long_to_bytes


f1 = open('./HUB1.txt','r')
f2 = open('./HUB2.txt','r')
content1 = f1.read().split()
content2 = f2.read().split()
n = int(content1[0])
e1 = int(content1[1])
e2 = int(content2[1])

result = open('result.txt','wb')
_, r, s = gmpy2.gcdext(e1, e2)
for i in range(2,len(content1)):
    c1 = int(content1[i])
    c2 = int(content2[i])
    m = pow(c1, r, n) * pow(c2, s, n) % n
    print(long_to_bytes(m))
    result.write(long_to_bytes(m))