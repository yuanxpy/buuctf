
memory = '0kk`d1a`55k222k2a776jbfgd`06cjjb'
temp1 = ''
for i in memory:
    temp = ord(i) ^ ord('S')
    temp1 += chr(temp)
print(temp1)

#md5解密 --123321

memory2 = [
  87, 94, 82, 84, 73, 95, 1, 109, 105, 70,
  2, 110, 95, 2, 108, 87, 91, 84, 76]

flag = ''
key = '123321'
for i in range(len(memory2)):
    temp = memory2[i] ^ ord(key[i%6])
    flag += chr(temp)
print(flag)