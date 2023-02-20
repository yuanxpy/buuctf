key = ['p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}']
for i in key:
    print(i,end='')
model = 'abcdefghijklmnopqrstuvwxyz'
for i in range(1,27):
    print('key=%d'%i)
    for s in key:
        if s.isalpha():
            n = model.find(s)
            s = model[n-i]
        print(s,end='')
    print("")