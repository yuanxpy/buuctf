import base64
import itertools
# new = "QWER7YUI0PASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbn/+m123456T89O"
new = "JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/"
old = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
de_table = ''.maketrans(new, old)

en_table = ''.maketrans(old, new)
# base_fix = b"flag{wow_you_find_the_real_table}"
# print(str(base64.b64encode(base_fix),encoding='utf-8').translate(en_table))



base_fix = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD=='
print(base64.b64decode(base_fix.translate(de_table)))

for i in old:
    if i  not in new:
        print(i,end=' ')
print()

for i in itertools.permutations('ju34'):
    baopo = i[0]+i[1]+i[2]+i[3]
    new = "JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs" + baopo + "kxyz012789+/"
    de_table = ''.maketrans(new, old)
    base_fix = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD=='
    result = (base64.b64decode(base_fix.translate(de_table)))
    if b"2020" in result:
        print(result)