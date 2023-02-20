en = [3,37,72,9,6,132]
output = [101,96,23,68,112,42,107,62,96,53,176,179,98,53,67,29,41,120,60,106,51,101,178,189,101,48]
flag = raw_input('please input your flag:')
str = flag
a = len(str)
if a>=38:
    print('lenth wrong!')
    exit(0)
if((((ord(str[1])+2020*ord(str[0]))*2020+ord(str[2]))*2020+ord(str[3]))*2020+ord(str[4])!=1182843538814603):
    exit(0)
x=[]
k=5
for i in range(13):
   b=ord(str[k])
   c=ord(str[k+1])
   a11=c^en[i%6]
   a22=b^en[i%6]
   x.append(a11)
   x.append(a22)
   k+=2
if x!=output:
    exit(0)
l=len(str)
a1=ord(str[l-7])
a2=ord(str[l-6])
a3=ord(str[l-5])
a4=ord(str[l-4])
a5=ord(str[l-3])
a6=ord(str[l-2])
if(a1*3+a2*2+a3*5==1003):
   if(a1*4+a2*7+a3*9==2013):
      if(a1+a2*8+a3*2==1109):
         if(a4*3+a5*2+a6*5==671):
            if(a4*4+a5*7+a6*9==1252):
               if(a4+a5*8+a6*2==644):
                  print('congraduation!you get the right flag!')
