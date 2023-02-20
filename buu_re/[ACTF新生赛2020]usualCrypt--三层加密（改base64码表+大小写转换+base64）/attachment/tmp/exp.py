import angr
p= angr.Project('./base.exe',auto_load_libs=False)#auto_load_libs是否加载依赖的库
state=p.factory.entry_state()#设置entry_state
simgr=p.factory.simgr(state)#创建一个simulation_manager进行模拟执行
simgr.one_active.options.add(angr.options.LAZY_SOLVES)
simgr.explore(find=0x40124E,avoid=[0x40125F,0x401230])#进行模拟执行
print(simgr.found[0].posix.dumps(0))#用simgr.found找到所有复合条件的分支,dumps可以获得文件输入的内容
#0表示的就是 stdin, 1 则是 stdout