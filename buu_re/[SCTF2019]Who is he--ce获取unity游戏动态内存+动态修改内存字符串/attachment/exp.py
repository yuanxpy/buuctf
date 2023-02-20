from Crypto.Cipher import DES
import base64

cipher = '1Tsy0ZGotyMinSpxqYzVBWnfMdUcqCMLu0MA+22Jnp+MNwLHvYuFToxRQr0c+ONZc6Q7L0EAmzbycqobZHh4H23U4WDTNmmXwusW4E+SZjygsntGkO2sGA=='



cipher1 = '71 00 2B 00 77 00 38 00 39 00 59 00 32 00 32 00 72 00 4F 00 62 00 66 00 7A 00 78 00 67 00 73 00 71 00 75 00 63 00 35 00 51 00 78 00 62 00 62 00 68 00 39 00 5A 00 49 00 41 00 48 00 45 00 54 00 2F 00 4E 00 6E 00 63 00 6D 00 69 00 71 00 45 00 6F 00 36 00 37 00 52 00 72 00 44 00 76 00 7A 00 33 00 34 00 63 00 64 00 41 00 6B 00 30 00 42 00 61 00 6C 00 4B 00 57 00 68 00 4A 00 47 00 6C 00 32 00 43 00 42 00 59 00 4D 00 6C 00 72 00 38 00 70 00 50 00 41 00 3D 00'
cipher1 = cipher1.split(' ')
temp = []
for i in cipher1:
    temp.append(chr(int(i,16)))
cipher1 = ''.join(temp).replace(' ','')
print(cipher1)


cipher2 = '78 00 5A 00 57 00 44 00 5A 00 61 00 4B 00 45 00 68 00 57 00 4E 00 4D 00 43 00 62 00 69 00 47 00 59 00 50 00 42 00 49 00 6C 00 59 00 33 00 2B 00 61 00 72 00 6F 00 7A 00 4F 00 39 00 7A 00 6F 00 6E 00 77 00 72 00 59 00 4C 00 69 00 56 00 4C 00 34 00 6E 00 6A 00 53 00 65 00 7A 00 32 00 52 00 59 00 4D 00 32 00 57 00 77 00 73 00 47 00 6E 00 73 00 6E 00 6A 00 43 00 44 00 6E 00 48 00 73 00 37 00 4E 00 34 00 33 00 61 00 46 00 76 00 4E 00 45 00 35 00 34 00 6E 00 6F 00 53 00 61 00 64 00 50 00 39 00 46 00 38 00 65 00 45 00 70 00 76 00 54 00 73 00 35 00 51 00 50 00 47 00 2B 00 4B 00 4C 00 30 00 54 00 44 00 45 00 2F 00 34 00 30 00 6E 00 62 00 55 00 3D'
cipher2 = cipher2.split(' ')
temp = []
for i in cipher2:
    temp.append(chr(int(i,16)))
cipher2 = ''.join(temp).replace(' ','')
print(cipher2)

key = b'1\x002\x003\x004\x00'
key2 = b't\x00e\x00s\x00t\x00'


generator = DES.new(key,DES.MODE_CBC,iv=key)
flag = generator.decrypt(base64.b64decode(cipher))
flag1 = generator.decrypt(base64.b64decode(cipher1))
generator = DES.new(key2,DES.MODE_CBC,iv=key2)
flag2 = generator.decrypt(base64.b64decode(cipher2))

print(flag.decode('utf-16'))
print(flag1.decode('utf-16'))
print(flag2.decode('utf-16'))