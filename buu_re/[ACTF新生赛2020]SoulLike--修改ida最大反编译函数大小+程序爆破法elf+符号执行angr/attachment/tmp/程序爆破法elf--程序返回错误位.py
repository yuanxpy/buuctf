from subprocess import Popen,PIPE

import re

path = './SoulLike'
# for i in range(4444444444):
flag = 'actf{'

position = 0
while 1:
    for i in range(33,128):
        key = (flag +chr(i)).ljust(17,'@') + '}'
        p = Popen (path,stdin = PIPE,stdout = PIPE)
        p.stdin.write(str(key).encode())##转成bytes
        result = p.communicate()[0]
        #printf("wrong on #%d\n", (unsigned int)i);
        # if b'true' in result:
        #     print(flag+'}')
        #     break
        try:
            false_position = re.findall(b"on #(.*?)\n", result)[0]
        except:
            print('第'+str(false_position)+'位爆破成功')
            print('返回结果',result)
            flag += chr(i)
            position += 1
            print(flag)
            break
        else:
            false_position = int(false_position)
            if false_position == position:
                print('第'+str(false_position)+'位爆破失败')
            elif false_position == position+1:
                print('第'+str(false_position)+'位爆破成功')
                flag += chr(i)
                print(flag)
                position += 1
                break
    if position == 12:
        break

