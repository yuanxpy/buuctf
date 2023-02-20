memory = [14, 13, 9, 6, 19, 5, 88, 86, 62, 6, 12, 60, 31, 87, 20, 107, 87, 89, 13]
memory2 = 'hahahaha_do_you_find_me?'
flag = ''
for i in range(19):
  temp = memory[i] ^ ord(memory2[i])
  flag += chr(temp)
print(flag)


#finally函数是随机验证有什么用，就纯用memoey3的最后一位和}异或（脑洞）
memory3 = '%tp&:'
print(ord(':')^ord('}'))
for i in memory3:
  flag += chr(ord(i)^71)

print(flag)