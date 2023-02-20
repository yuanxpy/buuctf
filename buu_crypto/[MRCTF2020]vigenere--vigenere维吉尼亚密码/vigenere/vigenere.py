#!/bin/python3
from ctf import source_text, key_string

getdiff = lambda char: ord(char)-ord('a')
getchar = lambda num: chr(ord('a')+num)

def vigenere(src: chr, key: chr) -> chr:
    assert(src.isalpha() and key.isalpha())
    return(getchar((getdiff(src) + getdiff(key) + 1) % 26))

src = source_text.lower()
count = 0
assert(len(key_string) > 5 and len(key_string) < 10)
for i in src:
    if(i.isalpha()):
        print(vigenere(i, key_string[count % len(key_string)]), end='')
        count+=1
    else:
        print(i, end='')

