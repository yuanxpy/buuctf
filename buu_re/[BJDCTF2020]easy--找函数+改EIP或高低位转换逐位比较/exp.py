key = [0x224FC7FFA7E31,0x22A84884A4239,0x3FF87084FF235,0x2318588424233,0x231FC7E4243F1]
#这里有需要注意的一点：第三位是0x3FF87084FF235而非0x3FF8784FF235
for i in key:
    count = 0
    temp = str(bin(i))[2:]
    #print(len(temp))
    for j in temp:
        if j == '0':
            print(" ",end='')
        else:
            print("*",end='')
        count = count + 1
        if count%5 == 0:
            print(" ",end='')
    print("")
