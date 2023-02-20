from Crypto.Util.number import inverse, long_to_bytes
cipher = '''41 96 C0 59 4A 5E 00 0A 96 B8 78 B6 7C D7 24 79
5B 13 A8 F2 CA 54 DA 06 D0 F1 9C 28 BE 68 9B 62
'''.replace(' ','').replace('\n','')
n = 0xC0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD
e = 65537
c = int(cipher,16)

p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

d = inverse(e,(p - 1) * (q - 1))
m = pow(c,d,n)
print(long_to_bytes(m))