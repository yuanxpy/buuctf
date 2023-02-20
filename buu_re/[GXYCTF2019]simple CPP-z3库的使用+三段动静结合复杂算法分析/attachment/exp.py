from z3 import *

f1,f2,f3,f4 = BitVecs('f1 f2 f3 f4',64)
#这里使用的是BitVecs，而不是Int，因为类型为 Int（注意这里的 Int 可不是 C/C++ 里面包含上下界的 int，Z3 中的 Int 对应的就是数学中的整数，Z3 中的 BitVector 才对应到 C/C++ 中的 int），这样我们才能实现一些无符号和有符号二进制运算
s = Solver()
s.add(f3&(~f1)==0x11204161012)
s.add((f3&(~f2))&f1|f3&((f2&f1)|f2&(~f1)|~(f2|f1))==0x8020717153E3013)
s.add((f3&(~f1))|(f2&f1)|(f3&(~f2))|(f1&(~f2))==0x3E3A4717373E7F1F)
s.add(f4==0x3E3A4717050F791F ^ 0x3E3A4717373E7F1F)
s.add(((f3&(~f1))|(f2&f1)|f2&f3)==((~f1)&f3|0xC00020130082C0C))
s.check()
result = s.model()
print(result)

memory = []
memory.append(hex(result[f1].as_long())[2:].rjust(16,'0'))
memory.append(hex(result[f2].as_long())[2:].rjust(16,'0'))
memory.append(hex(result[f3].as_long())[2:].rjust(16,'0'))
memory.append(hex(result[f4].as_long())[2:-2]) #这里容易出错
print(memory)

memory = ''.join(x for x in memory)
print(memory,len(memory))

Dst = 'i_will_check_is_debug_or_noi_wil'
flag = []
for i in range(0,len(memory),2):
    flag.append(int(memory[i:i+2],16))
print(flag)

s=''
for i in range(len(flag)):
    s+=chr(ord(Dst[i]) ^ flag[i])
print(s)


#原题目给的提示，buu里没有，好像是因为方程的多解导致的，我看我解出来的值确实和wp里的不一样
right_flag = ''
right_flag += s[:8]
right_flag += 'e!P0or_a'
right_flag += s[16:]
print(right_flag)