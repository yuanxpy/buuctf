import angr

p=angr.Project('attachment',auto_load_libs=False)

st = p.factory.entry_state()
sm = p.factory.simulation_manager(st)
# sm.one_active.options.add(angr.options.LAZY_SOLVES)
#这个语句在[GWCTF 2019]babyvm导致了运行angr脚本报错，注意下次报错时可以不使用该语句
sm.explore(find=[0x401081])

print(sm.found[0].posix.dumps(0))


