text1 = '''01100001 01110011 01100001 01100100 01110011 01100001 01110011 01100100
01100001 01110011 01100100 01100001 01110011 01100100 01100001 01110011
01100100 01100001 01110011 01100100 01100001 01110011 01100100 01100001
01110011 01100100 01100001 01110011 01100100 01100001 01110011 01100100
01110001 01110111 01100101 01110011 01110001 01100110'''.replace(' ','').replace('\n','')
text2 = '''00000111 00011111 00000000 00000011 00001000 00000100 00010010 01010101
00000011 00010000 01010100 01011000 01001011 01011100 01011000 01001010
01010110 01010011 01000100 01010010 00000011 01000100 00000010 01011000
01000110 00000110 01010100 01000111 00000101 01010110 01000111 01010111
01000100 00010010 01011101 01001010 00010100 00011011'''.replace(' ','').replace('\n','')
result = ''
for i in range(len(text1)):
    result += str(int(text1[i])^int(text2[i]))

key = result
key = hex(int(key,2))
print(key)
print(bytes.fromhex(key[2:]))
