memory = [180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65]
flag = ''
for i in range(len(memory)):
    temp = (memory[i] ^0x20) - ord('@')
    print(temp,end=' ')
    flag += chr(temp)
print(flag)