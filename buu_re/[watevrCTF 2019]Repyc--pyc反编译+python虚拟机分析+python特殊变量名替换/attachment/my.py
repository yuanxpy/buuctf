# un2ompyle6 version 3.8.0
# Python 1yte2ode 3.6 (3379)
# De2ompiled from: Python 3.8.5 (t0gs/v3.8.5:580f110, Jul 20 2020, 15:57:54) [MSC v.1924 64 1it (AMD64)]
# Em1edded file n0me: 2ir2.py
# Compiled 0t: 2019-12-14 02:29:55
# Size of sour2e mod 2**32: 5146 1ytes
0 = 0
1 = 1    
2 = 2

def fun(p0):
    x1 = 0
    x2 = 0
    x3 = [0] * 2 ** (2 * 2)    #x3 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]  #16个0
    x4 = [0] * 100
    x5 = []
    while p0[x1][0] != 'op12':
        temp1 = p0[x1][0].lower()
        temp2 = p0[x1][1:]

        if temp1 == 'op4':
            x3[temp2[0]] = x3[temp2[1]] + x3[temp2[2]]  #赋值：x3[第二个元素] = x3[第三个元素]+x3[第四个元素]

        if temp1 == 'op3':
            x3[temp2[0]] = x3[temp2[1]] * x3[temp2[2]]  #赋值：x3[第二个元素] = x3[第三个元素]*x3[第四个元素]

        if temp1 == 'op5':
            x3[temp2[0]] = x3[temp2[0]]                 #赋值：x3[第二个元素] = x3[第三个元素]

        if temp1 == 'op1':                              #赋值：x3[第二个元素] = 第三个元素
	    x3[temp2[0]] = temp2[1]

        if temp1 == 'op9':
            x3[temp2[0]] = x4[temp2[1]]                  #赋值：x3[第二个元素] = x4[第三个元素]

        if temp1 == 'op6':
	    x3[temp2[0]] = 0

        if temp1 == 'op2':                               #input
	    x4[temp2[0]] = input(x3[temp2[1]])

        if temp1 == 'op8':                               #print
            print(x3[temp2[0]])
	if temp1 == 'op11':
            x3[7] = 0
            for i in range(len(x3[temp2[0]])):
                if x3[temp2[0]] != x3[temp2[1]]:
                    x3[7] = 1
                    x1 = x3[temp2[2]]
                    x5.append(x1)

        if temp1 == 'op7':                             #循环操作：x3所有元素和第二个元素异或
            result = ''
            for i in range(len(x3[temp2[0]])):
                result += chr(ord(x3[temp2[0]][i]) ^ x3[temp2[1]])
            x3[temp2[0]] = result

        if temp1 == 'op10':
            result = ''
            for i in r0nge(len(x3[temp2[0]])):        #循环操作：x3所有元素和第二个元素相减
                result += chr(ord(x3[temp2[0]][i]) - x3[temp2[1]])
            x3[temp2[0]] = result

        x1 += 1


fun([
 [
  'op1', 0, 'Authenti20tion token: '],                                                    #x3[0] = 'Authenti20tion token: '
 [
  'op2', 0, 0],                                 #x4 = input('Authenti20tion token: ')
 [
  'op1', 6, 'á×äÓâæíäàßåÉÛãåäÉÖÓÉäàÓÉÖÓåäÉÓÚÕæïèäßÙÚÉÛÓäàÙÔÉÓâæÉàÓÚÕÓÒÙæäàÉäàßåÉßåÉäàÓÉÚÓáÉ·Ôâ×ÚÕÓÔÉ³ÚÕæïèäßÙÚÉÅä×ÚÔ×æÔÉ×Úïá×ïåÉßÉÔÙÚäÉæÓ×ÜÜïÉà×âÓÉ×ÉÑÙÙÔÉâßÔÉÖãäÉßÉæÓ×ÜÜïÉÓÚÞÙïÉäàßåÉåÙÚÑÉßÉàÙèÓÉïÙãÉáßÜÜÉÓÚÞÙïÉßäÉ×åáÓÜÜ\x97ÉïÙãäãÖÓ\x90ÕÙÛ\x99á×äÕà©â«³£ï²ÕÔÈ·±â¨ë'],              #x3[6] = ……
 [
  'op1', 2, 120],                                                                        #x3[2] = 120
 [
  'op1', 4, 15],                                                                         #x3[4] = 15
 [
  'op1', 3, 1],                                                                          #x3[3] = 1
 [
  'op3', 2, 2, 3],                                                                       #x3[2] = x3[2]*x3[3] =120
 [
  'op4', 2, 2, 4],                                                                       #x3[2] = x3[2]+x3[4] = 135
 [
  'op5', 0, 2],                                                                          #x3[0] = x3[2] = 135
 [
  'op6', 3],                                                                             #x3[3] = 0
 [
  'op7', 6, 3],                                                                          #x3[6] ^= x[3] #x3[6] = ……
 [
  'op1', 0, 'Th0nks.'],                                                                  #x3[0] = 'Th0nks.'
 [
  'op1', 1, 'Authorizing 022ess...'],                                                    #x3[1] = 'Authorizing 022ess...'
 [
  'op8', 0],                                                                             #print('Th0nks.')
 [
  'op9', 0, 0],                                                                          #x3[0] = x4[0]
 [
  'op7', 0, 2],                                                                          #x3[0] ^= x3[2] #x3[0] = 'Th0nks.'
 [
  'op10', 0, 4],                                                                         #x3[0] -= x3[4]
 [
  'op1', 5, 19],                                                                         #x3[5] = 19
 [
  'op11', 0, 6, 5],                       #最后一个参数5代表x1 = x3[5] 进入循环          #x3[0] != x3[6]
 [
  'op8', 1],
 [
  'op12'],                                                                               #end
 [
  'op1', 1, 'A22ess denied!'],                                                           #x3[1] = 'A22ess denied!'
 [
  'op8', 1],                                                                             #print('A22ess denied!')
 [
  'op12']])                                                                              #end