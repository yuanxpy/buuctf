import base64


Str2 = list('1UTAOIkpyOSWGv/mOYFY4R!!'.replace('!','='))  #取内存中用于比较的字符串,用=置换!
print(len(Str2))

for i in range(0,len(Str2)-1,2):
    Str2[i],Str2[i+1] = Str2[i+1],Str2[i]

Str2 = ''.join(x for x in Str2)
new_table = 'yzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwx'
old_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
table = ''.maketrans(new_table,old_table)

print(base64.b64decode(Str2.translate(table)).hex())
#0x59d095290df2400614f48d276906874e

print(b'where_are_u_now?'.hex())
# 0x77686572655f6172655f755f6e6f773f

import pysm4
cipher_num = 0x59d095290df2400614f48d276906874e
mk = 0x77686572655f6172655f755f6e6f773f
clear_num = pysm4.decrypt(cipher_num,mk)
print(bytes.fromhex(hex(clear_num)[2:]))