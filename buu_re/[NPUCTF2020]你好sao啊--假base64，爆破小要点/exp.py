table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234{}789+/="
c = "9E9B9C B5FE70 D30FB2 D14F9C 027FAB DE5965 63E740 9DCDFA"
c = c.split()
flag = ''
for i in range(len(c)):
    c[i] = eval("0x" + c[i])

print(c)
for x in c:
    t = 0
    for i in range(len(table)):
        for j in range(len(table)):
            for k in range(len(table)):
                for l in range(len(table)):
                    t = (0 << 6) | i
                    t = (t << 6) | j
                    t = (t << 6) | k
                    t = (t << 6) | l
                    if (t == x):
                        print(table[i] + table[j] + table[k] + table[l],' ',x)
                        if '='  not in (table[i] + table[j] + table[k] + table[l]):
                            flag += (table[i] + table[j] + table[k] + table[l])
print(flag)
print(len(flag))
#看大佬们的wp以为有什么特殊算法可以判断是不含=的字符串，后来发现其实不是的，三种字符串都可以满足程序要求