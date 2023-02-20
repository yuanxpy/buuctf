import angr
import claripy

p=angr.Project('./attachment',auto_load_libs=False)

state = p.factory.entry_state(addr=0x400605) #设置state开始运行时的地址
flag  = [claripy.BVS('flag_%d' % i, 8) for i in range(32)]
for i in range(32):
    state.mem[state.regs.rdx + 5 + i].byte = flag[i]
state.regs.rdi = state.regs.rdx + 5   #rdx指向字符串flag{之后的内容
sm = p.factory.simulation_manager(state)
sm.one_active.options.add(angr.options.LAZY_SOLVES)
print('ready')
sm.explore(find=[0x401DAE])

if sm.found:
    print('success')
    result = ''.join(chr(sm.one_found.solver.eval(c)) for c in flag)
    print(result)
else:
    print('error')