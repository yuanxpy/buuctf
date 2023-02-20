maze = '**************.****.**s..*..******.****.***********..***..**..#*..***..***.********************.**..*******..**...*..*.*.**.*'
print(len(maze))
count = 0
for i in range(0,len(maze),5):
    print(maze[i:i+5])
    count += 1
    if count == 5:
        count = 0
        print()
#d-右，a-左，w-上，s-下，x-降，y-升
#右右上上降降下下降左降上上左左下左下升升上上右
route = '右右上上降降下下降左降上上左左下左下升升上上右'
for i in route:
    if i == '右':
        print('d',end='')
    elif i == '左':
        print('a',end='')
    elif i == '上':
        print('w',end='')
    elif i == '下':
        print('s',end='')
    elif i == '升':
        print('y',end='')
    elif i == '降':
        print('x',end='')
print()




memory2 = 'sctf_9102'
memory2_1 = []
for i in range(0,len(memory2),3):
    memory2_1.append(hex(ord(memory2[i]))[2:]+hex(ord(memory2[i+1]))[2:]+hex(ord(memory2[i+2]))[2:])
# 736374
# 665f39
# 313032
x= [0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x3E, 0x7F, 0x7F, 0x7F, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x7F, 0x7F, 0x7F, 0x40, 0x7F, 0x7F,
    0x7F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F]
l=[0x736374,0x665f39,0x313032]
flag=[]
for a in range(len(l)):
	for i in range(32,len(x)):
		for j in range(31,len(x)):
			for k in range(31,len(x)):
				for m in range(31,len(x)):
					if ((((x[i]<<6|x[j])<<6)|x[k])<<6)|x[m]==l[a]:
						print(chr(i)+chr(j)+chr(k)+chr(m))
