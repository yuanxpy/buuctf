key = 'MSAWB~FXZ:J:`tQJ"N@ bpdd}8g'
flag = ''
for i in range(27):
    flag += chr(ord(key[i])^i)
print(flag)