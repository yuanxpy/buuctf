import base64
import string
s = 'R5UALCUVJDCGD63RQISZTBOSO54JVBORP5SAT2OEQCWY6CGEO53Z67L'
table = string.ascii_uppercase

for i in range(26):
    temp = ''
    for j in s:
        if j in table:
            temp += table[(table.find(j)+i)%26]
        else:
            temp += j
    print(temp)
    try:
        result = base64.b32decode(temp)
        print(result)
        break
    except:
        pass

print(base64.b32decode('O5RXIZRSGAZDA63ONFPWQYLPL54GSYLOM5PXQ2LBNZTV6ZDBL53W67I='))
#新约佛说解密+社会主义核心价值观编码+栅栏解密+凯撒位移3解密+base32解密
#有点坑注意下：
# 1.栅栏解密和凯撒解密要把上一轮解密得到结果末尾的提示去掉，一开始我解密没去掉结果出不来
# 2.base32直接用上面的脚本跑不出来，但是网站可以跑出来原因是网站会在字符串末尾补几个‘=’