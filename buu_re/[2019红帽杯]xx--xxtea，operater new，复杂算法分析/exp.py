import xxtea

result = 'CE BC 40 6B 7C 3A 95 C0 EF 9B 20 20 91 F7 02 35 23 18 02 C8 E7 56 56 FA'.split(" ")
res = [int(i,16) for i in result]


for i in range(7,-1,-1):
    t = 0
    for n in range(0,i):
        if t == 0 :
            t = res[0]
        else :
            t ^= res[n]
    for j in range(3) :
        res[i*3+j] ^= t

box = [1,3,0,2,5,7,4,6,9,11,8,10,13,15,12,14,17,19,16,18,21,23,20,22]
m = []


for i in range(len(box)):
    m.append(res[box[i]])


key = 'flag'+'\x00'*12

print(xxtea.decrypt(bytes(m),key,padding=False))