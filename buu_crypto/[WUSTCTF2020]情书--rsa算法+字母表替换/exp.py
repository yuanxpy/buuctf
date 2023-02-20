

a = "abcdefghijklmnopqrstuvwxyz"
c = "0156 0821 1616 0041 0140 2130 1616 0793".split(" ")
N = 2537
e = 13
d = 937
p = 43
q = 59

for i in c:
    temp = pow(int(i),d,N)
    print(a[temp],end='')
