#coding=utf8
from Crypto.PublicKey import DSA
from hashlib import sha1, md5
import gmpy2
with open('./dsa_public.pem', 'rb') as f:
    content = f.read()
    key = DSA.importKey(content)
    y = key.y
    g = key.g
    p = key.p
    q = key.q
f3 = open(r"packet3/message3", 'rb')
f4 = open(r"packet4/message4", 'rb')
data3 = f3.read()
data4 = f4.read()
sha = sha1()
sha.update(data3)
m3 = int(sha.hexdigest(), 16)
sha = sha1()
sha.update(data4)
m4 = int(sha.hexdigest(), 16)
print(m3, m4)
s3 = 0x30EB88E6A4BFB1B16728A974210AE4E41B42677D
s4 = 0x5E10DED084203CCBCEC3356A2CA02FF318FD4123
r = 0x5090DA81FEDE048D706D80E0AC47701E5A9EF1CC
ds = s4 - s3
dm = m4 - m3

# s1k = Hm1 + xr mod q
# s2k = Hm2 + x4 mod q
# k(s1 - s2) = Hm1 - Hm2 mod q
# k = (Hm1 - Hm2) / (s1 - s2)  mod q
k = gmpy2.mul(dm, gmpy2.invert(ds, q))
k = gmpy2.f_mod(k, q)
# x = (s1k - Hm1)/r mod q
tmp = gmpy2.mul(k, s3) - m3
x = tmp * gmpy2.invert(r, q)
x = gmpy2.f_mod(x, q)
print(hex(int(x)))

x = hex(int(x))
x = bytes.fromhex(x[2:])
print(md5(x).hexdigest())

