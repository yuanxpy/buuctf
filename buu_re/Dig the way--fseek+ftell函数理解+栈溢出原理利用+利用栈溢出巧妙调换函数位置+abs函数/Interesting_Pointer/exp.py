f = open('data','wb')
s = (20*'00'+4*3*'00'+'ffffffff'+'07000000'+'08000000')
f.write(bytes.fromhex(s))
f.close()


# f = open('data','rb')
# data = f.read()
# print(data)


