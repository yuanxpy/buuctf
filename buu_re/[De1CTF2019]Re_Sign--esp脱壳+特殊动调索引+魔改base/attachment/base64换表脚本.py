import base64
a = "0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/="
b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
data=[0x08,0x3b,0x01,0x20,0x07,0x34,0x09,0x1f,0x18,0x24,0x13,0x03,0x10,0x38,0x09,0x1b,
      0x08,0x34,0x13,0x02,0x08,0x22,0x12,0x03,0x05,0x06,0x12,0x03,0x0f,0x22,0x12,0x17,
      0x08,0x01,0x29,0x22,0x06,0x24,0x32,0x24,0x0f,0x1f,0x2b,0x24,0x03,0x15,0x41,0x41]

base_fix = ""
for i in data:
    base_fix += b[i - 1]
table = ''.maketrans(a, b)
print(base64.b64decode(base_fix.translate(table)))