key = '\x7Ffo`guci'
key1 = ''
print(len(key))
for i in range(8):
    if i % 2 == 1:
        key1 += chr(ord(key[7-i])-2)
    else:
        key1 += chr(ord(key[7-i])-1)
print('GXY{do_not_'+key1)