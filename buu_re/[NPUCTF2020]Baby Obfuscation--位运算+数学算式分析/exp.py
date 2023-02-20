memory = [  0,
  7801,
  7801,
  8501,
  5901,
  8001,
  6401,
  11501,
  4601,
  9801,
  9601,
  11701,
  5301,
  9701,
  10801,
  12501,
  0]


A0X4 = [2,3,4,5]
flag = ''
for i in range(len(memory)):
    temp = memory[i] // 100
    temp ^= A0X4[(i-1)%4]
    temp += A0X4[(i-1)%4]

    flag += chr(temp)
print(flag)

# m1[i_0] = ~(scanf_str[j-1] + AOX4[(k-1)%4])
#
# m1[j] ^= AOX4[(j-1)%4]
#
# m1[j] *= 8+2^(j+1)/j=10

