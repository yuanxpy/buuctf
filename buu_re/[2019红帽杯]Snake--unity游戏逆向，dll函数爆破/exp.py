#D:\desktop\ctf题目\buu_ctf\buu_re\[2019红帽杯]Snake\attachment\Snake\Snake_Data\Plugins

import ctypes

dll_path = 'D:\\desktop\\ctf题目\\buu_ctf\\buu_re\\[2019红帽杯]Snake--unity游戏逆向，dll函数爆破\\attachment\\Snake\\Snake_Data\\Plugins\\Interface.dll'

def baopo(i):
    dll = ctypes.cdll.LoadLibrary(dll_path)#进入interface.dll这个文件
    print(dll)
    print(i)
    dll.GameObject(i)#调用GameObject（）这个函数

for i in range(19,100):#从0~99开始爆破
    baopo(i)