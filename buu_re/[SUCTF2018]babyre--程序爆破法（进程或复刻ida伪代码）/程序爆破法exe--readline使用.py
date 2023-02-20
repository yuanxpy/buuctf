from subprocess import Popen,PIPE
# f = open('basic.txt','w')
path = 'attachment.exe'



for i in range(10000,0x10000):  #正常从0开始，但是我看过wp了，就直接从10000开始了，结果是12345
    key = str(i)
    p = Popen (path,stdin = PIPE,stdout = PIPE)
    p.stdout.readline()
    p.stdin.write(str(key).encode())  ##转成bytes
    result = p.communicate()[0]
    print(result)
    if b'SUCTF' in result :
        print(result,'爆破成功')
        print('密码为',key)
        break
    else:
        print(key,'爆破失败')

