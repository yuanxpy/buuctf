s = '111 114 157 166 145 123 145 143 165 162 151 164 171 126 145 162 171 115 165 143 150'.replace(' ','')
flag = ''
for i in range(0, len(s) - 1, 3):
    temp = s[i: i + 3]
    temp = chr(int(temp, 8))
    flag += temp

print(flag)