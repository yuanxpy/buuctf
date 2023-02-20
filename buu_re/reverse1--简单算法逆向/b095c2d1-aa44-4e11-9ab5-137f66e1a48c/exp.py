string = '{hello_world}'
string_list = []
for char in string:
    if ord(char) == 111:
        string_list.append(chr(48))
    else:
        string_list.append(char)
for char in string_list:
    print(char,end='')
