memory = ["=zqE=z=z=z","=lzzE","=ll=T=s=s=E","=zATT","=s=s=s=E=E=E","=EOll=E","=lE=T=E=E=E","=EsE=s=z","=AT=lE=ll"]
def ti_replace(s):
    s = s.replace("O", "0")
    s = s.replace("l", "1")
    s = s.replace("z", "2")
    s = s.replace("E", "3")
    s = s.replace("A", "4")
    s = s.replace("s", "5")
    s = s.replace("G", "6")
    s = s.replace("T", "7")
    s = s.replace("B", "8")
    s = s.replace("q", "9")
    s = s.replace("=", " ")
    return s
flag = ''
for i in range(len(memory)):
    temp = ti_replace(memory[i]).split()
    print(temp)
    sum = 1
    for j in range(len(temp)):
        sum *= int(temp[j],10)
    sum ^= 1
    flag += str(sum)
print(flag)

import hashlib
m = hashlib.md5()
m.update(bytes(flag,'utf-8'))
print(m.hexdigest().upper()) #32位md5大写