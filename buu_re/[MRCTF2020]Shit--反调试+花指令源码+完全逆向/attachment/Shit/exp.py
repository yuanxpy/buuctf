a = [0x8c2c133a,0xf74cb3f6,0xfedfa6f2,0xab293e3b,0x26cf8a2a,0x88a1f279]
k = [0x03,0x10,0x0d,0x04,0x13,0x0b]
for i in range(5,-1,-1):
    if i > 0:
        a[i] ^= a[i-1]
    a[i] ^= (1<<k[i])
    a[i] = ((a[i]>>16) | (~(a[i]<<16) & 0xffff0000) )
    a[i] = ((a[i] << k[i]) | (a[i] >> (32 - k[i])) )& 0xffffffff
flag = ''
print(a)
for i in range(len(a)):
    flag += (hex(a[i])[2:])
print(bytes.fromhex(flag))