string = [90,74,83,69,67,97,78,72,51,119,103]
string1 = []
for i in range(len(string)):
    string1.append(min(string))
    string.remove(min(string))
print(string1)



flag = [0 for i in range(8)]
flag[0] = chr(string1[0]+34)
flag[1] = chr(string1[4])
flag[2] = chr(int((3*string1[2]+141)/4))
flag[3] = chr(int((string1[7]/9)*2*4))
flag[4] = '1'
flag[5] = 'j'
flag[6] = 'M'
flag[7] = 'p'
#jMp-567     WP1-234
print('flag{',end='')
for char in flag:
    print(char,end='')
print('}')
