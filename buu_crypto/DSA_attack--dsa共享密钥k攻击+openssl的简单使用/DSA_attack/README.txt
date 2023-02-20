签名与验证：
openssl dgst -sha1 -sign dsa_private.pem -out sign.bin message.txt
openssl sha1 -verify dsa_public.pem -signature sign.bin message.txt

flag是私钥中不公开那一部分的MD5值(hex编码,不包括0x)。如：结果为"1024"，那么请提交 xnuca{MD5("\x0400")}
flag is the the MD5 hash value (hex encoded,excluding "0x") of secrect number in Private Key. For instance: if result is "1024",then submit xnuca{MD5("\x400")}