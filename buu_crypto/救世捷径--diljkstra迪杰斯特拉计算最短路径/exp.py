

graph = []
num = 27
for i in range(num):
    graph.append([])
for i in range(num):
    for j in range(num):
        graph[i].append(0x3f3f3f)
f = open('题目.txt').readlines()
li = []

for x in f:
    li.append(x.strip().split(' '))

# print(li)

for x in li:
    graph[int(x[0])][int(x[1])] = int(x[2])
    graph[int(x[1])][int(x[0])] = int(x[2])

def dijkstra():
    dv = [0x3f3f3f for i in range(num)]
    route=[1 for i in range(27)]#记录每点和与它对应的上一点
    used = [0 for i in range(num)]
    for i in range(2,num):
        dv[i] = graph[i][1]
    dv[1] = 0
    used[1] = 1
    for i in range(num - 1):
        minn = 0x3f3f3f
        for j in range(2,num):
            if used[j] == 0 and minn > dv[j]:
                minn = dv[j]
                temp = j
        used[temp] = 1

        for j in range(2,num):
            if dv[j] > dv[temp] + graph[temp][j]:
                dv[j] = dv[temp] + graph[temp][j]
                route[j]=temp
    return(route,dv)

route,dv = dijkstra()
print(dv[26])
print(route)
y = 26
while y != 1:
    print(y)
    y = route[y]