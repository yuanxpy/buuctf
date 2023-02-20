import angr

p=angr.Project('attachment.exe',auto_load_libs=False)

# st = p.factory.entry_state()
state = p.factory.blank_state(addr=0x004164F8) #恢复成addr处状态

simfd = state.posix.get_fd(0)# 创建一个标准输入对对象
data,real_size = simfd.read_data(22)# 注意该函数返回两个值 第一个是读到的数据内容 第二个数内容长度
state.memory.store(0x42612c,data)
#这里解释一下，我一开始搞了好久都不理解为什么要设置这个0x42612c的数据，感觉和主要逻辑没有任何关系。而且输出的结果也用的是这个数据
#后来突然想到输入字符串被改变了，所以尝试加入了一个text2输出，发现果然0x426020的输入被改变了（这种输入输出方式只能输出指定未知的数据）
#所以0x42612c其实就是为了保存输入数据而已，也即0x426020处的副本
state.memory.store(0x426020,data)

sm = p.factory.simulation_manager(state)
sm.one_active.options.add(angr.options.LAZY_SOLVES)
#这个语句在[GWCTF 2019]babyvm导致了运行angr脚本报错，注意下次报错时可以不使用该语句
sm.explore(find=[0x416610],avoid=[0x04164E2])

text = sm.one_found.solver.eval(sm.one_found.memory.load(0x0042612C,22),cast_to = bytes)

print(text)

# text2 = sm.one_found.solver.eval(sm.one_found.memory.load(0x426020,22),cast_to = bytes)
# print(text2)
# print(sm.found[0].posix.dumps(0))


