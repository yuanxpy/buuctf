maze = '*******+********* ******    ****   ******* **F******    **************'
print(len(maze))
for i in range(7):
    for j in range(10):
        print(maze[i*10+j],end='')
    print('')

#下下左左左下左左下下右右右上
route = '下下左左左下左左下下右右右上'
flag = ''
for char in route:
    if char == '左':
        flag += 'a'
    elif char == '右':
        flag += 'd'
    elif char == '下':
        flag += 's'
    else:
        flag += 'w'
print(flag)