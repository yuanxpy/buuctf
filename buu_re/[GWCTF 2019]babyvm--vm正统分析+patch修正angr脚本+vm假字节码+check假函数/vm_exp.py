code = [0x69, 0x45, 0x2A, 0x37, 0x09, 0x17, 0xC5, 0x0B, 0x5C, 0x72,
        0x33, 0x76, 0x33, 0x21, 0x74, 0x31, 0x5F, 0x33, 0x73, 0x72]

(code[13], code[19]) = (code[19], code[13])

(code[14], code[18]) = (code[18], code[14])
(code[15], code[17]) = (code[17], code[15])

from z3 import *

a = Real('a')
b = Real('b')
c = Real('c')
s = Solver()
s.add((c + 2 * b + 3 * a) * 0x33 == 0x6dC5)
s.add((0x72 + 2 * c + 3 * b) * 0x33 == 0x5b0b)
s.add((0x33 + 2 * 0x72 + 3 * c) * 0x33 == 0x705c)
if s.check() == sat:
    m = s.model()
    print(m)
code[6] = 118
code[7] = 51
code[8] = 95

for i in range(5, -1, -1):
    code[i] = code[i] ^ code[i + 1]
for i in range(20):
    print(chr(code[i]), end='')