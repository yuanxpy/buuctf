from Crypto.PublicKey import RSA
import libnum
import gmpy2
#导入公钥

n = 523798549
c = 162853095
#n 在线分解
p=10663
q=49123
inv_p = gmpy2.invert(p, q)
inv_q = gmpy2.invert(q, p)
mp = pow(c, (p + 1) // 4, p)
mq = pow(c, (q + 1) // 4, q)
a = (inv_p * p * mq + inv_q * q * mp) % n
b = n - int(a)
c = (inv_p * p * mq - inv_q * q * mp) % n
d = n - int(c)
#因为rabin 加密有四种结果，全部列出。
aa=[a,b,c,d]
for i in aa:
    # print(i)
    # print(bin(i))
    if bin(i)[-6:] == '110001':
        print(int(bin(i)[:-6],2))