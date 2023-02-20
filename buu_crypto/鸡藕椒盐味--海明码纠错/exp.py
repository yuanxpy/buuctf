import hashlib
text = b'110110100000'
md = hashlib.md5()
md.update(text)
print(md.hexdigest())