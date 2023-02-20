import string
import base64

old_table = string.ascii_uppercase+string.ascii_lowercase+string.digits+'+/'
new_table = "@,.1fgvw#`/2ehux$~\"3dity%_;4cjsz^+{5bkrA&=}6alqB*-[70mpC()]89noD"
table = ''.maketrans(new_table,old_table)
cypto = '_r-+_Cl5;vgq_pdme7#7eC0='
print(base64.b64decode(cypto.translate(table)))



