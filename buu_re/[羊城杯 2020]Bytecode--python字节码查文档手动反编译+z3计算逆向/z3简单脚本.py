from z3 import *
flag = ""
en = [3, 37, 72, 9, 6, 132]
output = [
    101, 96, 23, 68, 112, 42, 107, 62, 96, 53, 176, 179, 98, 53, 67, 29, 41,
    120, 60, 106, 51, 101, 178, 189, 101, 48
]
s = Solver()
a1 = [Int('a1[' + str(i) + ']') for i in range(5)]
s.add(((((a1[0] * 2020 + a1[1]) * 2020 + a1[2]) * 2020 + a1[3]) * 2020 +a1[4]) == 1182843538814603)
for i in range(5):
    s.add(a1[i] < 128)
    s.add(a1[i] > 30)

# if s.check():
#     print(s.model())

#结果即flag1
flag1 = [71, 87, 72, 84, 123]
for i in flag1:
    flag += chr(i)
print(flag)
############## WHT{
j = 0
flag2 = []
for i in range(13):
    flag2.append(chr(output[j + 1] ^ en[i % 6]))
    flag2.append(chr(output[j] ^ en[i % 6]))
    j += 2
for i in flag2:
    flag += i
print(flag)

ss = Solver()
a2 = [Int('a2[' + str(i) + ']') for i in range(6)]
ss.add((a2[0] * 4 + a2[1] * 7 + a2[2] * 9) == 2013)
ss.add((a2[0] + a2[1] * 8 + a2[2] * 2) == 1109)
ss.add((a2[3] * 3 + a2[4] * 2 + a2[5] * 5) == 671)
ss.add((a2[3] * 4 + a2[4] * 7 + a2[5] * 9) == 1252)
ss.add((a2[3] + a2[4] * 8 + a2[5] * 2) == 644)
for i in range(6):
    ss.add(a2[i] < 128)
    ss.add(a2[i] > 30)

# if ss.check():
#     print(ss.model())
#结果即flag3

flag3 = [51, 55, 102, 102, 101, 97]
flag3.reverse()
for i in flag3:
    flag += chr(i)
flag += '}'
print(flag)

