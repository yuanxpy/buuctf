import gmpy2
import rsa

e = 65537
n = 0xC0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463
d = gmpy2.invert(e,(p-1)*(q-1))
key = rsa.PrivateKey(n,e,int(d),p,q)
f = open("flag.enc","rb+")
fr = f.read()
print(rsa.decrypt(fr,key))