import requests
import urllib
import re
#
# f = open('目录.mhtml','r')
# f2 = open('目录提取.txt','w')
# content = f.readlines()
# for i in range(0,len(content)-3,3):
#     temp = content[i].strip() + content[i+1].strip() + content[i+2].strip()
#     print(temp)
#     url = re.search(r"\"(.*?)\"",temp)
#     print(url[1])
#     f2.write(url[1]+'\n')
# f.close()
# f2.close()


#
headers={
    'Host':'davidcheyenneone.github.io',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
}

f = open('目录提取.txt','r')
content = f.readlines()
for url in content:
    url = url.strip()
    print(url)
    r1 = requests.get(url=url,headers=headers)
    status = r1.status_code
    response=r1.text
    print(status)

    url = urllib.parse.unquote(url)
    r = re.search('BUUCTF/(.*)', url)
    name = r[1]
    print(name)

    f = open('./八神博客集合/'+name,'w',encoding="utf-8")
    f.write(response)
    f.close()



