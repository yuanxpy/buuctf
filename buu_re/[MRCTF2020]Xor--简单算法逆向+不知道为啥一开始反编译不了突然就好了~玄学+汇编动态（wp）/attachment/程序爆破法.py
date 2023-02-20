from subprocess import Popen,PIPE
# f = open('basic.txt','w')
path = 'xor.exe'

flag = 'MRCTF{@_R3@1ly_E2_R3verse'

for i in range(128):
    key = flag + chr(i) + '}'
    p = Popen (path,stdin = PIPE,stdout = PIPE)
    p.stdin.write(str(key).encode())##转成bytes
    result = p.communicate()[0]

    if b'Right!' in result:
        print(result,'爆破成功')
        print('密码为',key)
        break
    else:
        print(key,'爆破失败')

