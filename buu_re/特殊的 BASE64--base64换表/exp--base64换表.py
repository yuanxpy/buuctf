import base64
import string
new_table = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0987654321/+'
old_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
# old_table = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
trans = ''.maketrans(new_table,old_table)
miwen = 'mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI=='
print(base64.b64decode(miwen.translate(trans)))