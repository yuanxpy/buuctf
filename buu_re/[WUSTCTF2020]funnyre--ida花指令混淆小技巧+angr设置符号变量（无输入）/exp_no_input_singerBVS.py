import angr
import claripy

p=angr.Project('./attachment',auto_load_libs=False)

state = p.factory.entry_state(addr=0x400605) #设置state开始运行时的地址
flag = claripy.BVS('flag',8*32)  #要求的内容有32个，用BVS转成二进制给flag变量
# BVS类似于z3中的BitVec，第一个参数为变量名，第二个参数为位数(bit)
state.memory.store(0x603078+0x300+5,flag)#因为程序没有输入，所以直接把字符串设置到内存 ,0x300代表给字符串流出的空间，注意是大段序
state.regs.rdx = 0x603078+0x300     #rdx指向字符串
state.regs.rdi = 0x603078+0x300+5   #rdx指向字符串flag{之后的内容
sm = p.factory.simulation_manager(state)
sm.one_active.options.add(angr.options.LAZY_SOLVES)
print('ready')
sm.explore(find=[0x401DAE])

if sm.found:
    print('success')
    result = sm.found[0].solver.eval(flag,cast_to=bytes)
    #等价于 result = ''.join(chr(sm.one_found.solver.eval(c)) for c in flag_chars)
    #因为是手动设置的输入，不能通过dump(0) dump标准输入来得到输入，这里使用angr求解器提供的eval函数
    print(result)
else:
    print('error')








    # 因为使用标准输入经常无法推测输入字符串的长度，会浪费大量时间去尝试不同长度，所以我们可以自定义输入
    # 然后作为参数传入一个函数，这个时候state要设置为call的地址
    #
    # 复制代码
    # flag_chars = [BVS('flag_%d' % i, 32) for i in range(13)]
    # # BVS类似于z3中的BitVec，第一个参数为变量名，第二个参数为位数(bit) 这里我们知道输入了13个int 所以申请13个约束变量
    # for i in range(13):
    #     state.mem[state.regs.rsp + i * 4].dword = flag_chars[i]
    # # 这里为了方便 先把内容储存在rsp指向的内存 注意一个int是4字节
    # state.regs.rdi = state.regs.rsp  # 然后传参给rdi