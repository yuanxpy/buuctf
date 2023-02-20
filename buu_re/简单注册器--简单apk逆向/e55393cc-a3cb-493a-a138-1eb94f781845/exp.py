scanf_str = list( 0 for i in range(32))
scanf_str[0x1f] = chr(97)
scanf_str[1] = chr(98)
scanf_str[0] = chr(52)
scanf_str[2] = chr(52)
for i in scanf_str:
    print(i,end='')