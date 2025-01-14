from pwn import *

r = process("python3 ./chall.py", shell=True)
for i in range(1000):
    r.recvuntil(b'Question: ')
    eqn = r.recvline(keepends=False).decode()
    r.sendlineafter(b'Answer: ', str(eval(eqn)).encode())
r.interactive()