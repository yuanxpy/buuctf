from z3 import *
x = Int('x')
y = Int('y')
z = Int('z')
s = Solver()
s.add(x-y==0x84A236FF,y+z==0x0FA6CB703,x-z==0x42D731A8)
print(s.check())
print(s.model())
# [x = 3774025685, y = 1548802262, z = 2652626477]



a1 = [ 0 for i in range(6)]
a1[0] = -548868226  #0xDF48EF7E
a1[5] = -2064448480 #0x84F30420
a1[1] = 550153460
a1[2] = 3774025685
a1[3] = 1548802262
a1[4] = 2652626477


# a1[2] - a1[3] == 0x84A236FF
# a1[3] + a1[4] == 0x0FA6CB703
# a1[2] - a1[4] == 0x42D731A8
