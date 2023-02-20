import base64
key = '''Vm0wd2VHUXhTWGhpUm1SWVYw
ZDRWVll3Wkc5WFJs
bDNXa1pPVlUxV2NI
cFhhMk0xVmpKS1NH
VkdXbFpOYmtKVVZt
cEtTMUl5VGtsaVJt
Uk9ZV3hhZVZadGVH
dFRNVTVYVW01T2FG
SnRVbGhhVjNoaFZW
WmtWMXBFVWxSTmJF
cElWbTAxVDJGV1Nu
Tlhia0pXWWxob1dG
UnJXbXRXTVZaeVdr
Wm9hVlpyV1hwV1Iz
aGhXVmRHVjFOdVVs
WmlhMHBZV1ZSR1lW
ZEdVbFZTYlhSWFRW
WndNRlZ0TVc5VWJG
cFZWbXR3VjJKSFVY
ZFdha1pXWlZaT2Nt
RkhhRk5pVjJoWVYx
ZDBhMVV3TlhOalJs
cFlZbGhTY1Zscldu
ZGxiR1J5VmxSR1ZX
SlZjRWhaTUZKaFZq
SktWVkZZYUZkV1JW
cFlWV3BHYTFkWFRr
ZFRiV3hvVFVoQ1ds
WXhaRFJpTWtsM1RV
aG9hbEpYYUhOVmJU
VkRZekZhY1ZKcmRG
Tk5Wa3A2VjJ0U1Ex
WlhTbFpqUldoYVRV
WndkbFpxUmtwbGJV
WklZVVprYUdFeGNH
OVhXSEJIWkRGS2RG
SnJhR2hTYXpWdlZG
Vm9RMlJzV25STldH
UlZUVlpXTlZadE5V
OVdiVXBJVld4c1dt
SllUWGhXTUZwell6
RmFkRkpzVWxOaVNF
SktWa1phVTFFeFdu
UlRhMlJxVWxad1Yx
WnRlRXRXTVZaSFVs
UnNVVlZVTURrPQ=='''
key1 = 'Iodl>Qnb(ocy\x7fy.i\x7fd`3w}wek9{iy=~yL@EC'
print(len(key1))
info = ''
for i in range(36):
    info += chr(i^ord(key1[i]))
print(info)
print(key.replace('\n',''))
temp = bytes(key,'utf8')
for i in range(10):
    temp = base64.b64decode(temp)
print(temp)
flag = ''
flag_part = []
first = 'flag'
memory = [0x40,0x35,0x20,0x56,0x5D,0x18,0x22,0x45,0x17,0x2F,0x24,0x6E,0x62,0x3C,0x27,0x54,0x48,0x6C,0x24,0x6E,0x72,0x3C,0x32,0x45,0x5B]
for i in range(4):
    flag_part.append(ord(first[i])^memory[i])
for i in range(25):
    flag += chr(flag_part[i%4]^memory[i])
print(flag)