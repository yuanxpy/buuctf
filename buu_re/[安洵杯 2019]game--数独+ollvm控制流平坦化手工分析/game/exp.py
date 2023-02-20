complete_sudoku = [1, 4, 5, 3, 2, 7, 6, 9, 8, 8, 3, 9, 6, 5, 4, 1, 2, 7, 6, 7, 2, 8, 1,9, 5, 4, 3, 4, 9, 6, 1, 8, 5, 3, 7, 2, 2, 1, 8, 4, 7, 3, 9, 5, 6, 7,5, 3, 2, 9, 6, 4, 8, 1, 3, 6, 7, 5, 4, 2, 8, 1, 9, 9, 8, 4, 7, 6, 1,2, 3, 5, 5, 2, 1, 9, 3, 8, 7, 6, 4]
incomplete_sudoku = [1, 0, 5, 3, 2, 7, 0, 0, 8, 8, 0, 9, 0, 5, 0, 0, 2, 0, 0, 7, 0, 0, 1, 0, 5, 0, 3, 4, 9, 0, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0, 7, 0, 9, 0, 6, 7, 0, 3, 2, 9, 0, 4, 8, 0, 0, 6, 0, 5, 4, 0, 8, 0, 9, 0, 0, 4, 0, 0, 1, 0, 3, 0, 0, 2, 1, 0, 3, 0, 7, 0, 4]
flag = []
for i in range(81):
    if complete_sudoku[i] != incomplete_sudoku[i]:
        temp = ord(str(complete_sudoku[i]))+20  #ord()是因为check2（）里面有-48运算，就是数字从char类型转化为int
        flag.append(temp&0xf3 | ~temp&0xc)
print(flag)
for i in range(0,40,2):
    flag[i],flag[i+1] = flag[i+1],flag[i]
for i in range(20):
    flag[i],flag[20+i] = flag[20+i],flag[i]
print(''.join(chr(x) for x in flag))