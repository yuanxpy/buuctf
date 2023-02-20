result = '662e61257b26301d7972751d6b2c6f355f3a38742d74341d61776d7d7d'
result = bytes.fromhex(result)
count = 0
for i in result:
    if count % 2 == 0:
        print(chr(i),end='')
    else:
        print(chr(i^0x42),end='')
    count += 1