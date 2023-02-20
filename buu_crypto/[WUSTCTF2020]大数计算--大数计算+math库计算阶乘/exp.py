import math

def cal(x):
    temp = str(x)[:8]
    return int(temp)

p1 = cal(math.factorial(2020))
p2 = cal(520**1314 + 2333**666)
p3 = cal(80538738812075974 + 80435758145817515 + 12602123297335631)
p4 = (22**2+36)*1314
print("flag{"+hex(p1)[2:]+"-"+hex(p2)[2:]+"-"+hex(p3)[2:]+"-"+hex(p4)[2:]+"}")
