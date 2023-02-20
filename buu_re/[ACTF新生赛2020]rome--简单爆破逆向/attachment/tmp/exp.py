key = 'Qsw3sj_lz4_Ujw@l'
flag = 'ACTF{'
for k in range(len(key)):
    for s in range(128):
        i = s
        if i>64 and i<=90:
            i= (i-51)%26+65
        if i>96 and i<=122:
            i = (i-79)%26+97
        if i == ord(key[k]):
            flag+=chr(s)
print(flag+'}')
