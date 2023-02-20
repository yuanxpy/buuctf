string = '{hacking_for_fun}'
for i in range(len(string)):
    if string[i] == chr(105) or string[i] == chr(114):
        print(chr(49),end='')
    else:
        print(string[i],end='')