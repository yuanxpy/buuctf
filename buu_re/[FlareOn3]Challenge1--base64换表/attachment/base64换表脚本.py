
import base64
import string

oldtable = string.ascii_uppercase+string.ascii_lowercase+string.digits+'+/'
newtable = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/'

en_content = 'x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q'

table = ''.maketrans(newtable,oldtable)
print(base64.b64decode(en_content.translate(table)))
