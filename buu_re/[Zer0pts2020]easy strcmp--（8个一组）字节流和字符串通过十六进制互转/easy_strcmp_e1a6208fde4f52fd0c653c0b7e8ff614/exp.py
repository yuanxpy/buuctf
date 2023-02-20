import binascii

memory = [0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B]
key = '********CENSORED********'

flag = b''
for i in range(3):
    part_char = key[i*8:(i+1)*8]
    # part_num = binascii.b2a_hex(part_char.encode('ascii')[::-1])
    # part_cal = binascii.a2b_hex(hex(int(part_num,16) + memory[i])[2:])[::-1]
    part_num = binascii.hexlify(part_char.encode('ascii')[::-1])
    part_cal = binascii.unhexlify(hex(int(part_num,16) + memory[i])[2:])[::-1]

    flag += part_cal
print(flag)


# a2b_hex()：返回16进制的二进制数据表现形式 ,经测试等价于unhexlify
#
# b2a_hex()：返回二进制数据的16进制表现形式，经测试等价于hexlify
#
# hexlify()：返回二进制数据的16进制表现形式
#
# unhexlify()：返回16进制的二进制数据表现形式