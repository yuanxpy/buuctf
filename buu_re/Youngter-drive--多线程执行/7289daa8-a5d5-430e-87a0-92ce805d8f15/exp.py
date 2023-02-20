key1 = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm'
key2 = 'TOiZiZtOrYaToUwPnToBsOaOapsyS'
flag = ''
count = 0
for i in key2:
    temp = key1.find(i)
    print(temp)
    if temp >= 1 and temp <= 26:
        temp = temp + 96
    elif temp >= 27 and temp <= 52:
        temp = temp + 38
    if count % 2 == 0:
        flag += i
    else:
        flag += chr(temp)
    count = count + 1

print(flag,len(flag))
# print(65-38,90-38)
# print(97-96,122-96)
# 27 52
# 1 26

