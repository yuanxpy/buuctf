from z3 import *

x = Int('x')
y = Int('y')
z = Int('z')
solver = Solver()
solver.add(x*x+x-7943722218936282==0)
solver.add(x != -89127562)#第一次只求出这个负值，想要求出另一个值需要加上不等于的限制条件


# solver.add(3*x-y+z==185)
# solver.add(2*x+3*y-z==321)
# solver.add(x+y+z==173)
#
if solver.check() == sat:
    print(solver.model())