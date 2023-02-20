memory1=[
  9,
  10,
  15,
  23,
  7,
  24,
  12,
  6,
  1,
  16,
  3,
  17,
  32,
  29,
  11,
  30,
  27,
  22,
  4,
  13,
  19,
  20,
  21,
  2,
  25,
  5,
  31,
  8,
  18,
  26,
  28,
  14,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0
]
memory2 = [
  103,
  121,
  123,
  127,
  117,
  43,
  60,
  82,
  83,
  121,
  87,
  94,
  93,
  66,
  123,
  45,
  42,
  102,
  66,
  126,
  76,
  87,
  121,
  65,
  107,
  126,
  101,
  60,
  92,
  69,
  111,
  98,
  77,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0
]
flag = [0 for i in range(33)]
for i in range(33):
    temp = memory2[i] ^ (memory1[i] & 0xff)
    flag[memory1[i]] = temp
print(flag)
print(''.join([chr(x) for x in flag]))