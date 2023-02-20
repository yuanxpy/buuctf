import uncompyle6
with open("my1.py","w",encoding='utf8') as f:
    uncompyle6.decompile_file("3nohtyp.pyc", f)