
import os
def file_name(file_dir):
    for root,dirs,files in os.walk(file_dir):
        # print(root)#当前目录路径
        # print(dirs)#当前路径下所有子目录
        # print(files)#当前路径下所有非目录子文件
        return files
def Search(question):
    files = file_name('./')
    for i in files:
        f = open(i,'r',encoding='utf-8')
        content = f.read()
        if question in content:
            print(i)
            break


title = input("请输入要搜索的题目名字：")
Search(title)