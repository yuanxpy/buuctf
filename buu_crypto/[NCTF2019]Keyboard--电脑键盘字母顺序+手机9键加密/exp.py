#很巧妙，这些字母是26键盘的第一行，上面有对应数字，并且位数在1到4位，说明是九键键盘，刚好和题目意思对上了，
# 这种题写法就是比如o,对应9，就在九键键盘上9的位置，看o有多少位，3位的话，就是9那个位置字符串的第三个字符

s = 'ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee'
table = 'qwertyuiop'
a=[" ","abc","def","ghi","jkl","mno","pqrs","tuv","wxyz"," "]
for i in s.split(' '):
    temp = i[0]
    temp_len = len(i) - 1
    index = table.find(temp)
    result = a[index][temp_len]
    # print(temp,temp_len,index)
    print(result,end='')