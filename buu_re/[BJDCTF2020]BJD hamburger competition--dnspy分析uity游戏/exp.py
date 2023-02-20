import hashlib
key = 1001
key = hashlib.md5(bytes(str(key),encoding='utf-8')).hexdigest()
print(key)

