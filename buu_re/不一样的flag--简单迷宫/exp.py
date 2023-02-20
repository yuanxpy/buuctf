string = '*11110100001010000101111#'
for i in range(5):
    for j in range(5):
        print(string[5*i+j],end='')
    print("")
#下下下右右上上右右下下下
route = '下下下右右上上右右下下下'
flag = ''
for char in route:
    if char == '下':
        flag += '2'
    if char == '左':
        flag += '3'
    if char == '右':
        flag += '4'
    if char == '上':
        flag += '1'
print('flag{'+flag+'}')