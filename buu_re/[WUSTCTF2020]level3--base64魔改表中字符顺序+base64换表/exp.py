import string
b64_table = list(string.ascii_uppercase+string.ascii_lowercase+string.digits+'+/')
for i in range(10):
    v1 = b64_table[i]
    b64_table[i] = b64_table[19-i]
    result = 19-i
    b64_table[result] = v1
print(''.join(x for x in b64_table))

import base64
a = "TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

base_fix = "d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD=="
table = ''.maketrans(a,b)
print(table)
print(base64.b64decode(base_fix.translate(table)))