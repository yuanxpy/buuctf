string = '66 0A 6B 0C 77 26 4F 2E 40 11 78 0D 5A 3B 55 11 70 19 46 1F 76 22 4D 23 44 0E 67 06 68 0F 47 32 4F 00'
list = string.split(' ')
print(list)
flag= [0 for i in range(33)]
flag[0] = int(list[0],16)
print(chr(flag[0]),end='')
for i in range(1,33):
    flag[i] = int(list[i],16)^int(list[i-1],16)
    #print(flag[i])
    print(chr(flag[i]),end='')