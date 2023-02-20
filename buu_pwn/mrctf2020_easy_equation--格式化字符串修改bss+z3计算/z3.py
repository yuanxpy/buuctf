from z3 import *

judge = Int('judge')

solver = Solver()
solver.add(11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198)

if solver.check() == sat:
    result = solver.model()
    print(result)
else:
    print('出错了')