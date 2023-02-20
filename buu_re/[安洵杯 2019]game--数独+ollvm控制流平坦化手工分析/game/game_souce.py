arr = [1, 0, 5, 3, 2, 7, 0, 0, 8, 8, 0, 9, 0, 5, 0, 0, 2, 0, 0, 7, 0, 0, 1, 0, 5, 0, 3, 4, 9, 0, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0, 7, 0, 9, 0, 6, 7, 0, 3, 2, 9, 0, 4, 8, 0, 0, 6, 0, 5, 4, 0, 8, 0, 9, 0, 0, 4, 0, 0, 1, 0, 3, 0, 0, 2, 1, 0, 3, 0, 7, 0, 4]
dog3 = [1, 0, 5, 3, 2, 7, 0, 0, 8, 8, 0, 9, 0, 5, 0, 0, 2, 0, 0, 7, 0, 0, 1, 0, 5, 0, 3, 4, 9, 0, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0, 7, 0, 9, 0, 6, 7, 0, 3, 2, 9, 0, 4, 8, 0, 0, 6, 0, 5, 4, 0, 8, 0, 9, 0, 0, 4, 0, 0, 1, 0, 3, 0, 0, 2, 1, 0, 3, 0, 7, 0, 4]

def check2():
	v16 = []
	for i in range(len(flag)):
		v16.append(flag[v15] -48 )
	for i in range(9):
		for j in range(9):
			if  dog3[9 * i + j] == 0:
				dog3[9 *i + i] = v16[v13]
				v13 += 1
	for i in range(9):
		for j in range(9):
			if dog3[9 * i + j] != sudoku[9 * i + j]:
				print("!!!")

def check1():
	v12 = len(flag)>>1
	for i in range(len(flag)>>1):
		(flag[i],flag[v12+1]) = (flag[v12+1],flag[i])
		#前后两部分互换
	for i in range(0,len(flag),2):
		(flag[i],flag[i+1]) = (flag[i+1],flag[i])
		#两位之间互换
	for i in range(len(flag)):
		flag[i] = ((flag[i]&0xf3)|(~flag[i]&0xc)) - 20


def main():
	v4 = 0 
	for i in arr:
		if i == 0 :
			v4 += 1
	v13 = 0 
	print(v4)
	for i in range(9):
		print(arr[i:i+9])
	flag_s = input()
	flag = []
	for i in range(len(flag_s)):
		flag.append(flag_s[i])
