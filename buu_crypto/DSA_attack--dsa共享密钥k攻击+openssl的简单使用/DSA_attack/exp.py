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
s3 = 0x1B474F2C1C9E85B72841AD84D9A871A11EF0F323
s4 = 0x0EA21858C18AA1EDF4058B6EB9E02B0176243658
r = 0x12E780EE8471DC3552572BB6E818F6D22CE16EA4
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

