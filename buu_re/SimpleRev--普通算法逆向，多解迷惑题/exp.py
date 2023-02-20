key = 'ADSFKNDCLS'
key1 = ''
text = 'killshadow'
len_key = len(key)
for i in range(len_key):
    if ord(key[i%len_key])>64 and ord(key[i%len_key])<=90:
        key1 += chr(ord(key[i%len_key])+32)
    else:
        key1 += key[i]
print(key1)
flag = ''
#
loop = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

for i in range(len_key):
    for j in range(5):
        temp = (ord(text[i]) - 97) + 26 * j - 97 + 39 + ord(key1[i])
        if (temp>64 and temp<91) or (temp>96 and temp <123):
            flag += chr(temp)
            print(j)
            break
print('flag{'+flag+'}')

# for i in range(len(index)):
#     index2.append((index[i] - 39 -ord(key[i%len_key])+97)%26+97)
#     print(chr(index2[i]),end=' ')

