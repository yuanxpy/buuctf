import angr
import claripy

p=angr.Project('./oruga',auto_load_libs=False)

st = p.factory.entry_state()
sm = p.factory.simulation_manager(st)

sm.explore(find=[0x4009E7],avoid=[0x4009EE,0x4009B3])

print(sm.found[0].posix.dumps(0))