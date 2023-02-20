import angr
import claripy

p=angr.Project('./SoulLike',auto_load_libs=False)

st = p.factory.entry_state()
sm = p.factory.simulation_manager(st)
sm.one_active.options.add(angr.options.LAZY_SOLVES)

sm.explore(find=[0x41117D],avoid=[0x4111A1,0x41102D])

print(sm.found[0].posix.dumps(0))