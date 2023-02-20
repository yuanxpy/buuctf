
def next_instr(addr):
    return addr+idc.ItemSize(addr)  #ItemSize获取指令或数据长度，这个函数的作用就是去往下一条指令

st = 0x0000000000401117
end = 0x0000000000402144

addr = st
while(addr<end):
    next = next_instr(addr)
    if 'ds:dword_603054' in idc.GetDisasm(addr):  #GetDisasm(addr)得到addr的反汇编语句
        while(True):
            addr = next
            next = next_instr(addr)
            if 'jnz' in idc.GetDisasm(addr):
                dest = idc.GetOperandValue(addr,0)  #得到操作数，就是指令后的数
                idc.PatchByte(addr,0xe9)           #e9为汇编的代码jmp
                idc.PatchByte(addr+5,0x90)         #0f85为jnz的机器码占两个字节，故从jnz指令变为jmp指令需要nop掉最后一个字节
                offset = dest-(addr+5)
                idc.PatchDword(addr+1,offset)     #目标地址 = 当前指令地址 + 指令长度 + RVA
                print('0x%x has been patched'%addr)
                addr = next
                break
    else:
        addr = next