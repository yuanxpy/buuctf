key = 4
print(key)
memory=[13,  38,  73,  69,  42,  23, 120,  68,  43, 108,
   93,  94,  69,  18,  47,  23,  43,  68, 111, 110,
   86,   9,  95,  69,  71, 115,  38,  10,  13,  19,
   23,  72,  66,   1,  64,  77,  12,   2, 105]
print(len(memory))
flag = []

for i in range(len(memory)-1,-1,-1):
    flag.append(memory[i] ^ key)
    key = flag[-1]

print(''.join(chr(i) for i in flag[::-1]))


