from Crypto.PublicKey import RSA
f = open('public.key', 'rb').read()
pub = RSA.importKey(f)
n = pub.n
e = pub.e
print('n=',n)
print('e=',e)

