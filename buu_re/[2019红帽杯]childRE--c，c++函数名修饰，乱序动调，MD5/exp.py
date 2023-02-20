from hashlib import md5
string1 = '(_@4620!08!6_0*0442!@186%%0@3=66!!974*3234=&0^3&1@=&0908!6_0*&'
string2 = '55565653255552225565565555243466334653663544426565555525555222'
string3 = '1234567890-=!@#$%^&*()_+qwertyuiop[]QWERTYUIOP{}asdfghjkl;\'ASDFGHJKL:"ZXCVBNM<>?zxcvbnm,./'
output = []
print(len(string1))
for i in range(62):
    yu = (string3.index(string1[i]))
    shang = (string3.index(string2[i]))
    output.append(chr(shang*23+yu))
    print(chr(shang*23+yu),end='')
print(" ")
seq_scanf= '1234567890abcdefghijklmnopqrstu'
seq_print = 'fg8hi94jk0lma52nobpqc6rsdtue731'
seq = []
for i in range(len(seq_print)):
    seq.append(seq_scanf.index(seq_print[i]))
print(seq)

fun_name = '?My_Aut0_PWN@R0Pxx@@AAEPADPAE@Z'
flag_list = [0 for i in range(32)]
flag = ''
for i in range(31):
    flag_list[seq[i]] = fun_name[i]
for i in range(31):
    flag += flag_list[i]
print(flag)
print('flag{'+md5(flag.encode('utf8')).hexdigest()+'}')



