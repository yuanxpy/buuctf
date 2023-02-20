key = list('EmBmP5Pmn7QcPU4gLYKv5QcMmB3PWHcP5YkPq3=cT6QckkPckoRG')
#encode_three
for i in range(len(key)):
    temp = ord(key[i])
    if temp >= ord('0') and temp <= ord('9'):
        key[i] = (temp - 48 - 3 + 10) % 10 + 48
        continue
    if temp >= ord('a') and temp <= ord('z'):
        key[i] = (temp - 97 - 3 + 26) % 26 + 97
        continue
    if temp >= ord('A') and temp <= ord('Z'):
        key[i] = (temp - 65 -3 + 26) % 26 + 65
        continue
    else:
        key[i] = temp
print(''.join(chr(x) for x in key))
#encode_two  --> 3-1-4-2
part1 = key[0:13]
part2 = key[13:26]
part3 = key[26:39]
part4 = key[39:52]
key = part2+part4+part1+part3
print(''.join(chr(x) for x in key))
#encode_one
key = ''.join(chr(x) for x in key)
import base64
print(base64.b64decode(key))

