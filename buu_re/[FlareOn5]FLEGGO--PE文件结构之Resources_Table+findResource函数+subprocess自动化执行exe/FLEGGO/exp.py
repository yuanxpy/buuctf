import os
import subprocess

base_dir = './'
file_name = os.listdir()
for name in file_name:
    if name[-3:] != 'exe':
        continue
    key = ''
    f = open(name,'rb')
    key = f.read()[0x2ab0:0x2ad0]
    key = key.replace(b'\x00',b'')
    file_dir = base_dir + '\\' + name
    p = subprocess.Popen([file_dir],stdin=subprocess.PIPE,stdout = subprocess.PIPE,stderr=subprocess.PIPE)
    p.stdin.write(key)
    p.stdin.close()
    print(p.stdout.read())
    p.stdout.close()