from Crypto.Util.number import inverse,long_to_bytes
from base64 import b32decode,b64decode
from gmpy2 import gcd
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'

c = int(b64decode(c[::-1]))

q = n // p
phi = (p-1)*(q-1)
for e in range(50000,70001,1):
    while True:
        if gcd(e, phi) == 1:
            break
        else:
            e -= 1
    d = inverse(e,phi)
    m = pow(c,d,n)
    result = long_to_bytes(m)
    if b'flag' in result:
        print(result)
        break
