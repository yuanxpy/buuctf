import base64
y1 = [ 35, 97, 62, 105, 84, 65, 24, 77, 110, 59,
  101, 83, 48, 121, 69, 91]
y2 = [113, 4, 97, 88, 39, 30, 75, 34, 94, 100,
  3, 38, 94, 23, 60, 122]
flag = ''
print(len(y1),len(y2))
for i in range(16):
    flag += chr(y1[i]^y2[i])
flag += chr(0x3d)+chr(0x23)+chr(0x40)+str(base64.b64decode('YTFzMF9wV24='),encoding = "utf-8")
print(flag)
