import itertools
ciper = 'ouauuuoooeeaaiaeauieuooeeiea'
head = 'aeoiu'
headlist = []
num_headlist = []

# 先列举处aeiou五种的不同排序
x = itertools.permutations(head,5)
for i in x:
    temp = "".join(i)
    headlist.append(temp)
print(headlist)

# 根据aeiou对应的12345修改ciper的对应值，便于后续的遍历得到结果
for i in headlist:
    temp = ''
    for j in ciper:
        temp += str(i.index(j) + 1)
    num_headlist.append(temp)
print(num_headlist)

# 将ciper对应的数字乘上比例加上96再转为ASCII码，即 可得到对应的字母
for i in num_headlist:
    temp = ''
    for j in range(0,len(i),2):
        xx = (int(i[j]) - 1)*5 + int(i[j+1]) + 96   # 前一个为乘上5加上后一个就正好对应了表格中的字母
        if xx>ord('i'):
            xx+=1
        temp += chr(xx)
    if 'flag' in temp:
        print(temp)
