cipher = 'afZ_r9VYfScOeO_UL^RWUc'
print(ord('a')-ord('f'))
print(ord('f')-ord('l'))
print(ord('Z')-ord('a'))
print(ord('_')-ord('g'))
print(ord('r')-ord('{'))
print(ord('c')-ord('}'))
flag = []
key = 5
for i in cipher:
    temp = ord(i) + key
    key += 1
    flag.append(chr(temp))
print(''.join(flag))


