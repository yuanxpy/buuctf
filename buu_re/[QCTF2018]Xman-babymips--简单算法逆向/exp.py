part1 = 'Q|j{g'
part2 = [
  0x52, 0xFD, 0x16, 0xA4, 0x89, 0xBD, 0x92, 0x80, 0x13, 0x41,
  0x54, 0xA0, 0x8D, 0x45, 0x18, 0x81, 0xDE, 0xFC, 0x95, 0xF0,
  0x16, 0x79, 0x1A, 0x15, 0x5B, 0x75, 0x1F]
flag = ''
print(len(part2))
for i in range(len(part2)):
    if (i+5) & 1 != 0:
        part2[i] = (part2[i]&0x3f)<<2 | (part2[i]&0xc0)>>6  #相当于循环左移2位（里面的与操作是为了防止溢出）
    else:
        part2[i] = (part2[i]&0xfc)>>2 | (part2[i]&0x3)<<6
    flag += chr(part2[i]^0x20-i-5)

flag1 = ''
for i in range(len(part1)):
    temp = ord(part1[i])
    flag1 += chr(temp^0x20-i)
print(flag1+flag)