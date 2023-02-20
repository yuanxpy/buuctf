import base64
from Crypto.Cipher import AES

key = b'sycloversyclover'
iv = b"sctfsctfsctfsctf"
aes = AES.new(key, mode = AES.MODE_CBC, iv = iv)
res = b"nKnbHsgqD3aNEB91jB3gEzAr+IklQwT1bSs3+bXpeuo="
cipher = base64.b64decode(res)
tmp = aes.decrypt(cipher)
print(tmp)