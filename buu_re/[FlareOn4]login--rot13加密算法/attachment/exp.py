
key = 'PyvragFvqrYbtvafNerRnfl@syner-ba.pbz'
import string

def decoder(crypt_str,shift):
    crypt_list = list(crypt_str)
    plain_str = ""
    num = int(shift)
    for ch in crypt_list:
        ch = ord(ch)
        if ord('a') <= ch and ch <= ord('z'):
            ch = ch + num
            if ch > ord('z'):
                ch -= 26
        if ord('A') <= ch and ch <= ord('Z'):
            ch = ch +num
            if ch > ord('Z'):
                ch -= 26
        a=chr(ch)
        plain_str += a

    print(plain_str)

crypt_str = input("Crypto_text:")
print ("!------decode------!")
shift=13
decoder(crypt_str,shift)
