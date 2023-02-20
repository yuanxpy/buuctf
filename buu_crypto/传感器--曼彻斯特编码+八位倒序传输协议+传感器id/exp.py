# cipher = '5555555595555A65556AA696AA6666666955'

# for i in cipher:
#     temp = bin(int(i,16))
#     print(temp)


cipher = 0x5555555595555A65556AA696AA6666666955

s = '0'+ str(bin(cipher))[2:]
m = ''
for i in range(0,len(s),2):
    temp = s[i:i+2]
    if temp == '10':
        m += '0'
    elif temp == '01':
        m += '1'
    else:
        print(no)
        break
print(bin(int(m,2)))

#id = 0xFED31F

#八位倒序传输协议
result = bin(int(m,2))[2:]
result2 = ''
for i in range(0,len(result),8):
    temp = result[i:i+8]
    temp = temp[::-1]
    result2 += temp
print(hex(int(result2,2)).upper())